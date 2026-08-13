package main

import (
	"bytes"
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
	"path/filepath"
	"strings"
	"time"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}
type ReleaseManifest struct {
	Version   string `json:"version"`
	Protocol  int    `json:"protocol"`
	MinAgent  string `json:"min_agent"`
	MinServer string `json:"min_server"`
}

func verifyReleaseFile(file, checksums, signature, pubKey string) error {
	if file == "" || checksums == "" || signature == "" || pubKey == "" {
		return errors.New("--verify-file, --checksums, --signature and --public-key are required")
	}
	cb, err := os.ReadFile(checksums)
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}
	sb, err := os.ReadFile(signature)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	pb, err := os.ReadFile(pubKey)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pb)))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sb)))
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), cb, sigRaw) {
		return errors.New("Ed25519 signature verification failed")
	}
	name := filepath.Base(file)
	want := ""
	for _, line := range strings.Split(string(cb), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.TrimPrefix(f[len(f)-1], "*") == name {
			want = f[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("%s is not present in checksums.txt", name)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return errors.New("SHA256 verification failed")
	}
	return nil
}

func (a *App) latestRelease(r *http.Request) (githubRelease, ReleaseManifest, error) {
	a.mu.RLock()
	repo := a.state.Settings.ReleaseRepo
	a.mu.RUnlock()
	if !validRepo(repo) {
		repo = releaseRepo
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return githubRelease{}, ReleaseManifest{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "NodeLume-Server/"+serverVersion)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return githubRelease{}, ReleaseManifest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return githubRelease{}, ReleaseManifest{}, fmt.Errorf("GitHub returned HTTP %d", resp.StatusCode)
	}
	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return rel, ReleaseManifest{}, err
	}
	if !validVersion(rel.TagName) {
		return rel, ReleaseManifest{}, errors.New("latest release tag is not a semantic version")
	}
	base := "https://github.com/" + repo + "/releases/download/" + rel.TagName + "/"
	mb, err := downloadURL(base+"release-manifest.json", 1<<20)
	if err != nil {
		return rel, ReleaseManifest{}, fmt.Errorf("release manifest: %w", err)
	}
	cb, err := downloadURL(base+"checksums.txt", 2<<20)
	if err != nil {
		return rel, ReleaseManifest{}, fmt.Errorf("checksums: %w", err)
	}
	sb, err := downloadURL(base+"checksums.sig", 1<<20)
	if err != nil {
		return rel, ReleaseManifest{}, fmt.Errorf("signature: %w", err)
	}
	pubPath := envOr("NODELUME_RELEASE_PUBLIC_KEY", "/etc/nodelume/release.pub")
	if err := verifyReleaseBytes("release-manifest.json", mb, cb, sb, pubPath); err != nil {
		return rel, ReleaseManifest{}, fmt.Errorf("signed release metadata: %w", err)
	}
	var mf ReleaseManifest
	if err = json.Unmarshal(mb, &mf); err != nil {
		return rel, mf, err
	}
	if strings.TrimPrefix(rel.TagName, "v") != strings.TrimPrefix(mf.Version, "v") || mf.Protocol <= 0 {
		return rel, mf, errors.New("release manifest does not match release tag")
	}
	return rel, mf, nil
}

func downloadURL(url string, max int64) ([]byte, error) {
	c := &http.Client{Timeout: 12 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max+1))
}

func (a *App) updateStatus(w http.ResponseWriter, r *http.Request) {
	rel, mf, err := a.latestRelease(r)
	a.mu.RLock()
	agents := make([]map[string]any, 0, len(a.state.Nodes))
	for id, n := range a.state.Nodes {
		rt := a.runtime[id]
		status := "waiting"
		if n.Registered {
			status = "offline"
		}
		if rt != nil && !rt.LastSeen.IsZero() && time.Since(rt.LastSeen) < 30*time.Second {
			status = "online"
		}
		agents = append(agents, map[string]any{"id": id, "name": n.Name, "status": status, "version": n.System.Agent, "protocol": n.System.Protocol})
	}
	a.mu.RUnlock()
	out := map[string]any{"server_version": serverVersion, "protocol_version": protocolVersion, "agents": agents}
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 200, out)
		return
	}
	latest := strings.TrimPrefix(rel.TagName, "v")
	out["latest_version"] = latest
	out["latest_tag"] = rel.TagName
	out["release_url"] = rel.HTMLURL
	out["server_update_available"] = compareVersion(serverVersion, latest) < 0
	out["manifest"] = mf
	incompatible := 0
	for _, x := range agents {
		p, _ := x["protocol"].(int)
		v, _ := x["version"].(string)
		if p != 0 && p != mf.Protocol {
			incompatible++
		}
		if mf.MinAgent != "" && v != "" && compareVersion(v, mf.MinAgent) < 0 {
			incompatible++
		}
	}
	out["incompatible_agents"] = incompatible
	if b, er := os.ReadFile(a.updateStatusPath); er == nil {
		var st any
		if json.Unmarshal(b, &st) == nil {
			out["server_update_status"] = st
		}
	}
	writeJSON(w, 200, out)
}

func (a *App) requestServerUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &in, 1<<12) {
		return
	}
	target := strings.TrimPrefix(strings.TrimSpace(in.Version), "v")
	if !validVersion(target) {
		jsonError(w, "invalid version", 400)
		return
	}
	if compareVersion(serverVersion, target) >= 0 {
		jsonError(w, "server is already at this version or newer", 409)
		return
	}
	rel, mf, err := a.latestRelease(r)
	if err != nil {
		jsonError(w, "unable to verify release metadata: "+err.Error(), 503)
		return
	}
	if strings.TrimPrefix(rel.TagName, "v") != target {
		jsonError(w, "target is not the current published release", 409)
		return
	}
	if mf.Protocol != protocolVersion {
		jsonError(w, "target server protocol is incompatible", 409)
		return
	}
	a.mu.RLock()
	for _, n := range a.state.Nodes {
		if n.Registered && n.System.Protocol != 0 && n.System.Protocol != mf.Protocol {
			a.mu.RUnlock()
			jsonError(w, "one or more agents use an incompatible protocol; update agents first", 409)
			return
		}
		if mf.MinAgent != "" && n.System.Agent != "" && compareVersion(n.System.Agent, mf.MinAgent) < 0 {
			a.mu.RUnlock()
			jsonError(w, "one or more agents are below the minimum supported version", 409)
			return
		}
	}
	a.mu.RUnlock()
	req := map[string]any{"version": "v" + target, "requested_at": time.Now().Unix()}
	b, _ := json.Marshal(req)
	if err := atomicWrite(a.updateRequestPath, b, 0640); err != nil {
		jsonError(w, "unable to queue server update: "+err.Error(), 503)
		return
	}
	a.audit(a.remoteIP(r), "server_update", "", "v"+serverVersion+" -> v"+target, "queued")
	writeJSON(w, 202, map[string]any{"ok": true, "target_version": target, "message": "update queued"})
}

func (a *App) nodeUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &in, 1<<12) {
		return
	}
	target := strings.TrimPrefix(strings.TrimSpace(in.Version), "v")
	if !validVersion(target) {
		jsonError(w, "invalid version", 400)
		return
	}
	res, err := a.sendCommand(r.PathValue("id"), "agent_upgrade", AgentCommand{Version: target}, 45*time.Second)
	node := a.nodeName(r.PathValue("id"))
	if err != nil {
		a.audit(a.remoteIP(r), "agent_upgrade", node, "target v"+target, "failed: "+err.Error())
		jsonError(w, err.Error(), 503)
		return
	}
	if !res.OK {
		a.audit(a.remoteIP(r), "agent_upgrade", node, "target v"+target, "failed: "+res.Error)
		jsonError(w, res.Error, 502)
		return
	}
	a.audit(a.remoteIP(r), "agent_upgrade", node, "target v"+target, "installed; awaiting reconnect/health commit")
	writeJSON(w, 202, map[string]any{"ok": true, "target_version": target})
}

func verifyReleaseBytes(name string, data, checksums, signature []byte, pubKeyPath string) error {
	pb, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pb)))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), checksums, sigRaw) {
		return errors.New("release metadata signature verification failed")
	}
	want, err := checksumFor(checksums, name)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(want, hex.EncodeToString(sum[:])) {
		return errors.New("release metadata SHA256 verification failed")
	}
	return nil
}

func checksumFor(data []byte, name string) (string, error) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		f := bytes.Fields(line)
		if len(f) >= 2 && strings.TrimPrefix(string(f[len(f)-1]), "*") == name {
			return string(f[0]), nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found", name)
}
