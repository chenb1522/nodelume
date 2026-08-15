package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func nodeOfflineThreshold(n *PersistNode, rt *RuntimeNode) time.Duration {
	sec := 2
	// Prefer the interval the Agent has actually reported. The desired interval
	// can change before the Agent applies it, and using that new value here can
	// incorrectly mark an otherwise-online node offline during the transition.
	if rt != nil && rt.Latest.ReportIntervalSec > 0 {
		sec = rt.Latest.ReportIntervalSec
	} else if n != nil && n.ReportIntervalSec > 0 {
		sec = n.ReportIntervalSec
	}
	d := time.Duration(sec*3) * time.Second
	if d < 30*time.Second {
		d = 30 * time.Second
	}
	return d
}
func nodeIsOnline(n *PersistNode, rt *RuntimeNode) bool {
	return n != nil && n.Registered && rt != nil && !rt.LastSeen.IsZero() && time.Since(rt.LastSeen) < nodeOfflineThreshold(n, rt)
}

func domainAccessURL(domain, listen string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		port = "443"
	}
	if port == "443" {
		return "https://" + domain
	}
	return "https://" + net.JoinHostPort(domain, port)
}

func (a *App) measureHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 {
			a.httpRX.Add(uint64(r.ContentLength))
		}
		cw := &countWriter{ResponseWriter: w}
		next.ServeHTTP(cw, r)
		a.httpTX.Add(uint64(cw.n))
	})
}

type countWriter struct {
	http.ResponseWriter
	n int64
}

func (w *countWriter) Write(b []byte) (int, error) {
	n, e := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, e
}

func (w *countWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (a *App) getListenSettings(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	desired := a.state.Settings.Listen
	a.mu.RUnlock()
	if desired == "" {
		desired = a.activeListen
	}
	writeJSON(w, 200, map[string]any{"active": a.activeListen, "desired": desired, "pending": desired != a.activeListen})
}
func parseListen(address string, port int) (string, error) {
	address = strings.TrimSpace(address)
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("端口必须在 1–65535 之间")
	}
	if address == "" {
		return "", fmt.Errorf("请输入监听 IP 地址")
	}
	if ip := net.ParseIP(address); ip == nil && address != "localhost" {
		return "", fmt.Errorf("请输入有效的监听 IP 地址")
	}
	return net.JoinHostPort(address, strconv.Itoa(port)), nil
}
func listenPort(addr string) string {
	_, p, e := net.SplitHostPort(addr)
	if e != nil {
		return ""
	}
	return p
}
func (a *App) saveListenSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
	}
	if !decodeJSON(w, r, &in, 1<<14) {
		return
	}
	target, err := parseListen(in.Address, in.Port)
	if err != nil {
		jsonErrorCode(w, "INVALID_LISTEN", err.Error(), "", 400)
		return
	}
	if target != a.activeListen && listenPort(target) != listenPort(a.activeListen) {
		ln, er := net.Listen("tcp", target)
		if er != nil {
			jsonErrorCode(w, "PORT_IN_USE", fmt.Sprintf("监听地址 %s 不可用：%v", target, er), "请选择未占用端口", 409)
			return
		}
		_ = ln.Close()
	}
	a.mu.Lock()
	old := a.state.Settings.Listen
	a.state.Settings.Listen = target
	a.auditLocked(a.remoteIP(r), "listen_settings", "", fmt.Sprintf("%s -> %s", old, target), "success")
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "保存失败", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "active": a.activeListen, "desired": target, "pending": target != a.activeListen})
}
func (a *App) restartServer(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	target := a.state.Settings.Listen
	a.mu.RUnlock()
	if target == "" {
		target = a.activeListen
	}
	a.audit(a.remoteIP(r), "server_restart", "", target, "requested")
	writeJSON(w, 202, map[string]any{"ok": true, "target": target})
	go func() { time.Sleep(350 * time.Millisecond); os.Exit(75) }()
}

func (a *App) selfStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.serverSelfStats())
}
func (a *App) serverSelfStats() SelfStats {
	a.selfMu.Lock()
	defer a.selfMu.Unlock()
	now := time.Now()
	if !a.selfCacheAt.IsZero() && now.Sub(a.selfCacheAt) < 5*time.Second {
		return a.selfCache
	}
	st := SelfStats{RXBytes: a.httpRX.Load(), TXBytes: a.httpTX.Load()}
	st.RSSBytes = procRSSBytes(os.Getpid())
	st.CPUPercent = procAverageCPU(os.Getpid())
	st.DiskBytes, st.Inodes = ownedUsage([]string{filepath.Dir(a.dataPath), a.acmeDir, filepath.Join(filepath.Dir(a.dataPath), "logs")})
	if !a.selfPrevAt.IsZero() {
		sec := now.Sub(a.selfPrevAt).Seconds()
		if sec > 0 {
			st.RXRate = float64(st.RXBytes-a.selfPrevRX) / sec
			st.TXRate = float64(st.TXBytes-a.selfPrevTX) / sec
		}
	}
	a.selfPrevRX, a.selfPrevTX, a.selfPrevAt = st.RXBytes, st.TXBytes, now
	a.selfCache, a.selfCacheAt = st, now
	return st
}
func procRSSBytes(pid int) uint64 {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if e != nil {
		return 0
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "VmRSS:" {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			return v * 1024
		}
	}
	return 0
}
func procAverageCPU(pid int) float64 {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+2:])
	if len(f) < 20 {
		return 0
	}
	ut, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	start, _ := strconv.ParseFloat(f[19], 64)
	upb, e := os.ReadFile("/proc/uptime")
	if e != nil {
		return 0
	}
	up, _ := strconv.ParseFloat(strings.Fields(string(upb))[0], 64)
	const hz = 100.0
	elapsed := up - start/hz
	if elapsed <= 0 {
		return 0
	}
	return (ut + st) / hz / elapsed * 100
}
func ownedUsage(paths []string) (uint64, uint64) {
	seen := map[string]bool{}
	var bytes, inodes uint64
	for _, root := range paths {
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			inodes++
			if !d.IsDir() {
				if st, e := d.Info(); e == nil {
					bytes += uint64(st.Size())
				}
			}
			return nil
		})
	}
	return bytes, inodes
}

func (a *App) allowEnrollment(ip string) bool {
	now := time.Now().Unix()
	a.enrollRateMu.Lock()
	defer a.enrollRateMu.Unlock()
	xs := a.enrollRate[ip][:0]
	for _, t := range a.enrollRate[ip] {
		if now-t < 60 {
			xs = append(xs, t)
		}
	}
	if len(xs) >= 20 {
		a.enrollRate[ip] = xs
		return false
	}
	xs = append(xs, now)
	a.enrollRate[ip] = xs
	return true
}

// Keep imports used on older Go versions when response streaming changes.
var _ io.Writer

func (a *App) writeRuntimeStatus() {
	s := a.serverSelfStats()
	content := fmt.Sprintf("VERSION=v%s\nPROTOCOL=%d\nLISTEN=%s\nCPU_PERCENT=%.3f\nRSS_BYTES=%d\nDISK_BYTES=%d\nINODES=%d\nRX_BYTES=%d\nTX_BYTES=%d\nRX_RATE=%.3f\nTX_RATE=%.3f\n",
		serverVersion, protocolVersion, a.activeListen, s.CPUPercent, s.RSSBytes, s.DiskBytes, s.Inodes, s.RXBytes, s.TXBytes, s.RXRate, s.TXRate)
	_ = atomicWrite("/run/nodelume-server/status.env", []byte(content), 0640)
}
