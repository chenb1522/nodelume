package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type pendingUpdate struct {
	Previous    string `json:"previous"`
	Current     string `json:"current"`
	Target      string `json:"target"`
	InstalledAt int64  `json:"installed_at"`
}

func performAgentUpgrade(version, repo, pubKey string, startWatchdog bool) error {
	version = strings.TrimPrefix(version, "v")
	if !validVersion(version) || !validRepo(repo) {
		return errors.New("版本号或 Release 仓库无效")
	}
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("不支持的 CPU 架构 %s", arch)
	}
	base := releaseBase(repo, "v"+version)
	name := "nodelume-agent-linux-" + arch
	dir, err := os.MkdirTemp("", "nodelume-agent-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, name)
	checks := filepath.Join(dir, "checksums.txt")
	sig := filepath.Join(dir, "checksums.sig")
	for _, x := range []struct {
		url, path string
		max       int64
	}{{base + name, bin, 64 << 20}, {base + "checksums.txt", checks, 2 << 20}, {base + "checksums.sig", sig, 1 << 20}} {
		if err = downloadFile(x.url, x.path, x.max); err != nil {
			return err
		}
	}
	if err = verifySignedFile(bin, checks, sig, pubKey); err != nil {
		return fmt.Errorf("Release 校验失败: %w", err)
	}
	if err = os.Chmod(bin, 0755); err != nil {
		return err
	}
	ctx, cancel := contextWithTimeout(7 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--self-check")
	if out, er := cmd.CombinedOutput(); er != nil {
		return fmt.Errorf("新二进制自检失败: %s", strings.TrimSpace(string(out)))
	}
	ctxVer, cancelVer := contextWithTimeout(5 * time.Second)
	verOut, er := exec.CommandContext(ctxVer, bin, "--version").CombinedOutput()
	cancelVer()
	if er != nil || !strings.Contains(string(verOut), "NodeLume Agent v"+version+" ") {
		return fmt.Errorf("新二进制版本与目标版本 %s 不一致", version)
	}
	current, err := os.Executable()
	if err != nil {
		return err
	}
	current, err = filepath.EvalSymlinks(current)
	if err != nil {
		return err
	}
	previous := current + ".previous"
	_ = os.Remove(previous)
	if err = os.Rename(current, previous); err != nil {
		return fmt.Errorf("备份当前二进制失败: %w", err)
	}
	if err = os.Rename(bin, current); err != nil {
		_ = os.Rename(previous, current)
		return fmt.Errorf("安装新二进制失败: %w", err)
	}
	_ = os.Chmod(current, 0755)
	p := pendingUpdate{Previous: previous, Current: current, Target: version, InstalledAt: time.Now().Unix()}
	if err = writePending(p); err != nil {
		_ = os.Remove(current)
		_ = os.Rename(previous, current)
		return err
	}
	if startWatchdog {
		go agentRollbackWatchdog(p)
	}
	return nil
}

func releaseBase(repo, tag string) string {
	if b := strings.TrimRight(os.Getenv("NODELUME_RELEASE_BASE"), "/"); b != "" {
		return b + "/" + tag + "/"
	}
	return "https://github.com/" + repo + "/releases/download/" + tag + "/"
}
func downloadFile(url, path string, max int64) error {
	c := &http.Client{Timeout: 25 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("下载 %s 失败: HTTP %d", filepath.Base(path), resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, max+1))
	if err != nil {
		return err
	}
	if n > max {
		return errors.New("下载内容超过大小限制")
	}
	return f.Sync()
}
func verifySignedFile(file, checksums, signature, pubKey string) error {
	cb, err := os.ReadFile(checksums)
	if err != nil {
		return err
	}
	sb, err := os.ReadFile(signature)
	if err != nil {
		return err
	}
	pb, err := os.ReadFile(pubKey)
	if err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pb)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("Ed25519 公钥无效")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sb)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("Ed25519 签名无效")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), cb, sig) {
		return errors.New("签名不匹配")
	}
	want := ""
	name := filepath.Base(file)
	for _, line := range strings.Split(string(cb), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.TrimPrefix(f[len(f)-1], "*") == name {
			want = f[0]
			break
		}
	}
	if want == "" {
		return errors.New("校验清单中缺少目标二进制")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if !strings.EqualFold(want, hex.EncodeToString(sum[:])) {
		return errors.New("SHA256 校验不匹配")
	}
	return nil
}
func writePending(p pendingUpdate) error {
	if err := os.MkdirAll(filepath.Dir(pendingUpdatePath), 0700); err != nil {
		return err
	}
	b, _ := json.Marshal(p)
	tmp := pendingUpdatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, pendingUpdatePath)
}
func rollbackAgentBinary() error {
	b, err := os.ReadFile(pendingUpdatePath)
	if err != nil {
		return err
	}
	var p pendingUpdate
	if err = json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.Previous == "" || p.Current == "" {
		return errors.New("待处理更新状态无效")
	}
	failed := p.Current + ".failed"
	_ = os.Remove(failed)
	if _, er := os.Stat(p.Current); er == nil {
		_ = os.Rename(p.Current, failed)
	}
	if err = os.Rename(p.Previous, p.Current); err != nil {
		return err
	}
	_ = os.Chmod(p.Current, 0755)
	_ = os.Remove(pendingUpdatePath)
	return nil
}
func commitAgentUpdate() error {
	b, err := os.ReadFile(pendingUpdatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var p pendingUpdate
	if err = json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.Previous != "" {
		_ = os.Remove(p.Previous)
	}
	return os.Remove(pendingUpdatePath)
}
func agentRollbackWatchdog(p pendingUpdate) {
	delay := 38 * time.Second
	if v := strings.TrimSpace(os.Getenv("NODELUME_UPDATE_WATCHDOG_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 2 && n <= 300 {
			delay = time.Duration(n) * time.Second
		}
	}
	time.Sleep(delay)
	if !fileExists(pendingUpdatePath) {
		return
	}
	_ = rollbackAgentBinary()
	if sys := systemctlPath(); sys != "" {
		_ = exec.Command(sys, "restart", "nodelume-agent.service").Run()
	}
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
