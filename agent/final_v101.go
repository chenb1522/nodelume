package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SelfStats struct {
	CPUPercent float64 `json:"cpu_percent"`
	RSSBytes   uint64  `json:"rss_bytes"`
	DiskBytes  uint64  `json:"disk_bytes"`
	Inodes     uint64  `json:"inodes"`
	RXBytes    uint64  `json:"rx_bytes"`
	TXBytes    uint64  `json:"tx_bytes"`
	RXRate     float64 `json:"rx_rate"`
	TXRate     float64 `json:"tx_rate"`
}

var agentNetRX, agentNetTX atomic.Uint64
var agentSelfMu sync.Mutex
var agentSelfCache SelfStats
var agentSelfCacheAt, agentSelfPrevAt time.Time
var agentSelfPrevRX, agentSelfPrevTX uint64

type countingTransport struct{ base http.RoundTripper }
type countingBody struct{ io.ReadCloser }

func (b *countingBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if n > 0 {
		agentNetRX.Add(uint64(n))
	}
	return n, e
}
func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.ContentLength > 0 {
		agentNetTX.Add(uint64(r.ContentLength))
	}
	resp, err := t.base.RoundTrip(r)
	if err == nil && resp.Body != nil {
		resp.Body = &countingBody{resp.Body}
	}
	return resp, err
}
func agentHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &countingTransport{base: http.DefaultTransport}}
}

func agentSelfStats(configPath string) SelfStats {
	agentSelfMu.Lock()
	defer agentSelfMu.Unlock()
	now := time.Now()
	if !agentSelfCacheAt.IsZero() && now.Sub(agentSelfCacheAt) < 5*time.Second {
		return agentSelfCache
	}
	st := SelfStats{RXBytes: agentNetRX.Load(), TXBytes: agentNetTX.Load(), RSSBytes: selfRSSBytes()}
	st.CPUPercent = selfAverageCPU()
	roots := []string{filepath.Dir(configPath), "/var/lib/nodelume-agent-helper"}
	if exe, err := os.Executable(); err == nil {
		roots = append(roots, exe)
	}
	st.DiskBytes, st.Inodes = agentOwnedUsage(roots)
	if !agentSelfPrevAt.IsZero() {
		sec := now.Sub(agentSelfPrevAt).Seconds()
		if sec > 0 {
			if st.RXBytes >= agentSelfPrevRX {
				st.RXRate = float64(st.RXBytes-agentSelfPrevRX) / sec
			}
			if st.TXBytes >= agentSelfPrevTX {
				st.TXRate = float64(st.TXBytes-agentSelfPrevTX) / sec
			}
		}
	}
	agentSelfPrevRX, agentSelfPrevTX, agentSelfPrevAt = st.RXBytes, st.TXBytes, now
	agentSelfCache, agentSelfCacheAt = st, now
	return st
}
func selfRSSBytes() uint64 {
	b, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return 0
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "VmRSS:" {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			return v * 1024
		}
	}
	return 0
}
func selfAverageCPU() float64 {
	b, e := os.ReadFile("/proc/self/stat")
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
	uf := strings.Fields(string(upb))
	if len(uf) == 0 {
		return 0
	}
	up, _ := strconv.ParseFloat(uf[0], 64)
	const hz = 100.0
	elapsed := up - start/hz
	if elapsed <= 0 {
		return 0
	}
	return (ut + st) / hz / elapsed * 100
}
func agentOwnedUsage(paths []string) (uint64, uint64) {
	seen := map[string]bool{}
	var b, n uint64
	for _, root := range paths {
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		st, e := os.Stat(root)
		if e != nil {
			continue
		}
		if !st.IsDir() {
			b += uint64(st.Size())
			n++
			continue
		}
		_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, e error) error {
			if e != nil {
				return nil
			}
			n++
			if !d.IsDir() {
				if x, e := d.Info(); e == nil {
					b += uint64(x.Size())
				}
			}
			return nil
		})
	}
	return b, n
}

type APIError struct {
	Status               int
	Code, Reason, Action string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s (Action: %s)", e.Code, e.Reason, e.Action)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Reason)
}
func decodeAPIError(resp *http.Response) *APIError {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var v struct {
		Error  string `json:"error"`
		Code   string `json:"code"`
		Reason string `json:"reason"`
		Action string `json:"action"`
	}
	_ = json.Unmarshal(b, &v)
	reason := v.Reason
	if reason == "" {
		reason = v.Error
	}
	if reason == "" {
		reason = strings.TrimSpace(string(b))
	}
	return &APIError{Status: resp.StatusCode, Code: v.Code, Reason: reason, Action: v.Action}
}

func isAgentSubcommand(s string) bool {
	switch s {
	case "help", "status", "config", "test", "bind", "set", "version":
		return true
	}
	return false
}
func maybeRunAgentSubcommand(args []string) (bool, int) {
	if len(args) == 0 || !isAgentSubcommand(args[0]) {
		return false, 0
	}
	return true, runAgentSubcommand(args)
}
func cliConfigPath(args *[]string) string {
	p := "/var/lib/nodelume-agent/agent.json"
	for i := 0; i < len(*args); i++ {
		if (*args)[i] == "--config" && i+1 < len(*args) {
			p = (*args)[i+1]
			*args = append((*args)[:i], (*args)[i+2:]...)
			break
		}
	}
	return p
}
func runAgentSubcommand(args []string) int {
	cmd := args[0]
	args = args[1:]
	path := cliConfigPath(&args)
	if cmd == "help" {
		fmt.Print("NodeLume Agent CLI\n  status\n  config\n  test [-s, --server URL]\n  bind -s, --server URL -t, --token TOKEN [-n, --name NAME]\n  set -s, --server URL | -l, --log-level LEVEL\n  version\n")
		return 0
	}
	if cmd == "version" {
		fmt.Printf("NodeLume Agent v%s (protocol %d)\n", agentVersion, protocolVersion)
		return 0
	}
	cfg, err := loadConfig(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "Code    CONFIG_READ_FAILED\nReason ", err)
		return 1
	}
	switch cmd {
	case "config":
		b, _ := json.MarshalIndent(redactedConfig(cfg), "", "  ")
		fmt.Println(string(b))
		return 0
	case "status":
		state := "未绑定"
		if cfg.NodeID != "" && cfg.Secret != "" {
			state = "已绑定"
		}
		fmt.Printf("NodeLume Agent\n状态      %s\n版本      v%s\nProtocol  %d\nServer    %s\n节点      %s\n", state, agentVersion, protocolVersion, blankDash(cfg.Server), blankDash(cfg.Name))
		return 0
	case "test":
		server := cfg.Server
		for len(args) > 0 {
			switch args[0] {
			case "-s", "--server":
				if len(args) < 2 {
					return 2
				}
				server = strings.TrimRight(args[1], "/")
				args = args[2:]
			default:
				return 2
			}
		}
		if server == "" {
			fmt.Fprintln(os.Stderr, "Code    SERVER_REQUIRED\nReason  未配置 Server")
			return 2
		}
		if err := validateServerURL(server); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err := testServer(server, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "❌ Agent 测试失败\n", err)
			return 3
		}
		fmt.Println("✅ Server 可达且 Protocol/身份检查通过")
		return 0
	case "set":
		server, level := "", ""
		for len(args) > 0 {
			switch args[0] {
			case "-s", "--server":
				if len(args) < 2 {
					return 2
				}
				server = strings.TrimRight(args[1], "/")
				args = args[2:]
			case "-l", "--log-level":
				if len(args) < 2 {
					return 2
				}
				level = args[1]
				args = args[2:]
			default:
				return 2
			}
		}
		next := cfg
		if server != "" {
			if err := validateServerURL(server); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			next.Server = server
			if cfg.NodeID != "" && cfg.Secret != "" {
				if err := testAuthenticatedServer(server, next); err != nil {
					fmt.Fprintln(os.Stderr, "Code    SERVER_IDENTITY_CHECK_FAILED\nReason ", err, "\nAction  原 Server 配置未修改")
					return 3
				}
			} else if !verifyEndpoint(server) {
				fmt.Fprintln(os.Stderr, "Code    SERVER_UNREACHABLE\nAction  原配置未修改")
				return 3
			}
		}
		if level != "" {
			switch level {
			case "debug", "info", "warn", "error":
				next.LogLevel = level
			default:
				fmt.Fprintln(os.Stderr, "日志级别只允许 debug/info/warn/error")
				return 2
			}
		}
		if next == cfg {
			fmt.Println("没有需要修改的配置")
			return 0
		}
		if err := saveConfig(path, next); err != nil {
			fmt.Fprintln(os.Stderr, "Code    CONFIG_SAVE_FAILED\nReason ", err)
			return 1
		}
		fmt.Println("✅ Agent 配置已更新")
		return 0
	case "bind":
		server, token, name := "", "", ""
		for len(args) > 0 {
			switch args[0] {
			case "-s", "--server":
				if len(args) < 2 {
					return 2
				}
				server = strings.TrimRight(args[1], "/")
				args = args[2:]
			case "-t", "--token":
				if len(args) < 2 {
					return 2
				}
				token = args[1]
				args = args[2:]
			case "-n", "--name":
				if len(args) < 2 {
					return 2
				}
				name = args[1]
				args = args[2:]
			default:
				return 2
			}
		}
		if server == "" || token == "" {
			fmt.Fprintln(os.Stderr, "Code    ARGUMENT_ERROR\nReason  bind 需要 -s Server 和 -t Token")
			return 2
		}
		if err := validateServerURL(server); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		next := cfg
		next.Server = server
		next.Name = name
		next.ConfigVersion = 2
		if next.ReportIntervalSec == 0 {
			next.ReportIntervalSec = 2
		}
		if next.ReleaseRepo == "" {
			next.ReleaseRepo = releaseRepo
		}
		next.EnrollmentToken = token
		next.NodeID = ""
		next.Secret = ""
		sampler := newSampler()
		var rr RegisterResponse
		client := agentHTTPClient(15 * time.Second)
		req := RegisterRequest{Token: token, Name: name, EnrollmentID: enrollmentID(next), AgentVersion: "v" + agentVersion, Protocol: protocolVersion, System: sampler.sys}
		if err := doJSON(client, "POST", server+"/api/agent/register", "", req, &rr); err != nil {
			fmt.Fprintln(os.Stderr, "Code    ENROLLMENT_FAILED\nReason ", err, "\nAction  原绑定未修改")
			return 3
		}
		next.NodeID, next.Secret, next.EnrollmentToken = rr.NodeID, rr.Secret, ""
		if rr.ReportIntervalSec > 0 {
			next.ReportIntervalSec = rr.ReportIntervalSec
		}
		if err := testAuthenticatedServer(server, next); err != nil {
			fmt.Fprintln(os.Stderr, "Code    IDENTITY_VERIFY_FAILED\nReason ", err, "\nAction  原绑定未修改")
			return 3
		}
		if err := saveConfig(path, next); err != nil {
			fmt.Fprintln(os.Stderr, "Code    IDENTITY_SAVE_FAILED\nReason ", err, "\nAction  原绑定文件未覆盖")
			return 1
		}
		fmt.Printf("✅ Agent 绑定成功\n节点      %s\nServer    %s\nProtocol  %d\n", blankDash(next.Name), server, protocolVersion)
		return 0
	}
	return 2
}
func redactedConfig(c Config) map[string]any {
	b, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["secret"]; ok {
		m["secret"] = "********"
	}
	if _, ok := m["enrollment_token"]; ok {
		m["enrollment_token"] = "********"
	}
	return m
}
func blankDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
func testServer(base string, cfg Config) error {
	c := agentHTTPClient(6 * time.Second)
	resp, err := c.Get(strings.TrimRight(base, "/") + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var h struct {
		Protocol int `json:"protocol_version"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&h); err != nil {
		return err
	}
	if h.Protocol != protocolVersion {
		return fmt.Errorf("SERVER_PROTOCOL_TOO_OLD/AGENT_PROTOCOL_TOO_OLD: Server Protocol %d 与 Agent Protocol %d 不兼容", h.Protocol, protocolVersion)
	}
	if cfg.NodeID != "" && cfg.Secret != "" {
		return testAuthenticatedServer(base, cfg)
	}
	return nil
}
func testAuthenticatedServer(base string, cfg Config) error {
	c := agentHTTPClient(8 * time.Second)
	req, _ := http.NewRequest("GET", strings.TrimRight(base, "/")+"/api/agent/commands?wait=1", nil)
	signRequest(req, nil, cfg)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 || resp.StatusCode == 204 {
		return nil
	}
	return decodeAPIError(resp)
}

func writeAgentRuntimeStatus(configPath string, s SelfStats, cfg Config) {
	state := "unbound"
	if cfg.NodeID != "" && cfg.Secret != "" && cfg.Server != "" {
		state = "bound"
	}
	content := fmt.Sprintf("VERSION=v%s\nPROTOCOL=%d\nSTATE=%s\nNODE_ID=%s\nNAME=%s\nSERVER=%s\nINTERVAL=%d\nCPU_PERCENT=%.3f\nRSS_BYTES=%d\nDISK_BYTES=%d\nINODES=%d\nRX_BYTES=%d\nTX_BYTES=%d\nRX_RATE=%.3f\nTX_RATE=%.3f\n",
		agentVersion, protocolVersion, state, cfg.NodeID, strings.ReplaceAll(cfg.Name, "\n", " "), strings.ReplaceAll(cfg.Server, "\n", " "), cfg.ReportIntervalSec,
		s.CPUPercent, s.RSSBytes, s.DiskBytes, s.Inodes, s.RXBytes, s.TXBytes, s.RXRate, s.TXRate)
	_ = os.MkdirAll("/run/nodelume-agent", 0750)
	tmp := "/run/nodelume-agent/status.env.tmp"
	if err := os.WriteFile(tmp, []byte(content), 0640); err == nil {
		_ = os.Rename(tmp, "/run/nodelume-agent/status.env")
	}
	_ = configPath
}
