package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var agentVersion = "1.0.0"
var releaseRepo = "chenb1522/nodelume"

const protocolVersion = 1
const helperSocket = "/run/nodelume-agent/helper.sock"
const stoppedPath = "/var/lib/nodelume-agent-helper/stopped.json"
const pendingUpdatePath = "/var/lib/nodelume-agent-helper/update/pending.json"

type Config struct {
	Server            string `json:"server"`
	EnrollmentToken   string `json:"enrollment_token,omitempty"`
	NodeID            string `json:"node_id,omitempty"`
	Secret            string `json:"secret,omitempty"`
	ReleaseRepo       string `json:"release_repo,omitempty"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http,omitempty"`
}
type ConfigState struct {
	mu   sync.RWMutex
	cfg  Config
	path string
}

func (s *ConfigState) get() Config { s.mu.RLock(); defer s.mu.RUnlock(); return s.cfg }
func (s *ConfigState) set(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := saveConfig(s.path, c); err != nil {
		return err
	}
	s.cfg = c
	return nil
}

type SystemInfo struct {
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	OSID        string `json:"os_id"`
	Arch        string `json:"arch"`
	Kernel      string `json:"kernel"`
	CPUModel    string `json:"cpu_model"`
	CPUCores    int    `json:"cpu_cores"`
	MemoryTotal uint64 `json:"memory_total"`
	Agent       string `json:"agent"`
	Protocol    int    `json:"protocol"`
}
type ProcessSummary struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	CPU        float64 `json:"cpu"`
	MemoryMB   float64 `json:"memory_mb"`
	MemoryPct  float64 `json:"memory_pct"`
	User       string  `json:"user"`
	State      string  `json:"state"`
	UptimeSecs int64   `json:"uptime_secs,omitempty"`
}
type ProcessDetail struct {
	ProcessSummary
	Command      string `json:"command"`
	Launch       string `json:"launch"`
	Service      string `json:"service,omitempty"`
	Parent       string `json:"parent,omitempty"`
	Exe          string `json:"exe,omitempty"`
	Cwd          string `json:"cwd,omitempty"`
	Tree         string `json:"tree,omitempty"`
	Protected    bool   `json:"protected"`
	CanTerminate bool   `json:"can_terminate"`
	CanKill      bool   `json:"can_kill"`
	CanRestart   bool   `json:"can_restart"`
	RestartMode  string `json:"restart_mode,omitempty"`
	Note         string `json:"note,omitempty"`
}
type StoppedRecord struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Launch    string   `json:"launch"`
	Service   string   `json:"service,omitempty"`
	StoppedAt int64    `json:"stopped_at"`
	CanStart  bool     `json:"can_start"`
	Note      string   `json:"note,omitempty"`
	Exe       string   `json:"-"`
	Args      []string `json:"-"`
	Cwd       string   `json:"-"`
	UID       uint32   `json:"-"`
	GID       uint32   `json:"-"`
}
type Heartbeat struct {
	Time        int64            `json:"time"`
	CPU         float64          `json:"cpu"`
	Memory      float64          `json:"memory"`
	MemoryUsed  uint64           `json:"memory_used"`
	MemoryAvail uint64           `json:"memory_available"`
	Disk        float64          `json:"disk"`
	DiskUsed    uint64           `json:"disk_used"`
	DiskTotal   uint64           `json:"disk_total"`
	Temperature *float64         `json:"temperature,omitempty"`
	Load1       float64          `json:"load1"`
	Load5       float64          `json:"load5"`
	Load15      float64          `json:"load15"`
	NetIn       float64          `json:"net_in"`
	NetOut      float64          `json:"net_out"`
	Uptime      float64          `json:"uptime"`
	Processes   int              `json:"processes"`
	TopCPU      []ProcessSummary `json:"top_cpu"`
	TopMemory   []ProcessSummary `json:"top_memory"`
	System      SystemInfo       `json:"system"`
}
type AgentCommand struct {
	Protocol  int    `json:"protocol"`
	ID        string `json:"request_id"`
	Action    string `json:"action"`
	Timestamp int64  `json:"timestamp"`
	PID       int    `json:"pid,omitempty"`
	Version   string `json:"version,omitempty"`
	RestartID string `json:"restart_id,omitempty"`
	Unit      string `json:"unit,omitempty"`
}
type AgentResult struct {
	RequestID string          `json:"request_id"`
	Action    string          `json:"action"`
	OK        bool            `json:"ok"`
	Error     string          `json:"error,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}
type RegisterRequest struct {
	Token  string     `json:"token"`
	System SystemInfo `json:"system"`
}
type RegisterResponse struct {
	NodeID string `json:"node_id"`
	Secret string `json:"secret"`
}
type HeartbeatResponse struct {
	OK             bool   `json:"ok"`
	ServerURL      string `json:"server_url"`
	ServerProtocol int    `json:"server_protocol"`
}
type DiskInfo struct {
	Name    string  `json:"name"`
	Mount   string  `json:"mount"`
	FSType  string  `json:"fs_type"`
	Used    uint64  `json:"used"`
	Total   uint64  `json:"total"`
	Percent float64 `json:"percent"`
}
type PortInfo struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

type cpuTimes struct{ total, idle uint64 }
type procCPU struct{ ticks uint64 }
type Sampler struct {
	mu                    sync.Mutex
	sys                   SystemInfo
	lastCPU               cpuTimes
	lastNetIn, lastNetOut uint64
	lastNetAt             time.Time
	procTicks             map[int]procCPU
	lastProcTotal         uint64
	topCPU, topMem        []ProcessSummary
	lastProcScan          time.Time
}

func main() {
	configPath := flag.String("config", "/var/lib/nodelume-agent/agent.json", "config file")
	server := flag.String("server", "", "server URL")
	token := flag.String("token", "", "one-time enrollment token")
	allowInsecureHTTP := flag.Bool("allow-insecure-http", false, "allow plain HTTP to a non-loopback Server (unsafe; testing only)")
	helper := flag.Bool("helper", false, "run privileged local helper")
	helperSock := flag.String("helper-socket", "", "helper socket for non-systemd tests")
	showVersion := flag.Bool("version", false, "print version")
	selfCheck := flag.Bool("self-check", false, "validate binary")
	upgradeSelf := flag.String("upgrade-self", "", "install signed target version without restarting service")
	rollback := flag.Bool("rollback", false, "restore previous agent binary")
	commit := flag.Bool("commit-update", false, "commit pending agent update")
	repoFlag := flag.String("repo", releaseRepo, "release repository")
	pubKey := flag.String("public-key", "/etc/nodelume/release.pub", "Ed25519 release public key")
	verifyFile := flag.String("verify-file", "", "verify a release file")
	checksums := flag.String("checksums", "", "checksums.txt for --verify-file")
	signature := flag.String("signature", "", "checksums.sig for --verify-file")
	flag.Parse()
	if *showVersion {
		fmt.Printf("NodeLume Agent v%s (protocol %d)\n", agentVersion, protocolVersion)
		return
	}
	if *verifyFile != "" {
		if err := verifySignedFile(*verifyFile, *checksums, *signature, *pubKey); err != nil {
			fatalf("release verification: %v", err)
		}
		fmt.Println("release verification OK")
		return
	}
	if *selfCheck {
		fmt.Printf("NodeLume Agent v%s self-check OK\n", agentVersion)
		return
	}
	if *helper {
		if err := runHelper(*helperSock); err != nil {
			fatalf("helper: %v", err)
		}
		return
	}
	if *rollback {
		if err := rollbackAgentBinary(); err != nil {
			fatalf("rollback: %v", err)
		}
		fmt.Println("rollback OK")
		return
	}
	if *commit {
		if err := commitAgentUpdate(); err != nil {
			fatalf("commit: %v", err)
		}
		fmt.Println("update commit OK")
		return
	}
	if *upgradeSelf != "" {
		if os.Geteuid() != 0 {
			fatalf("--upgrade-self must run as root")
		}
		if err := performAgentUpgrade(strings.TrimPrefix(*upgradeSelf, "v"), *repoFlag, *pubKey, false); err != nil {
			fatalf("upgrade: %v", err)
		}
		fmt.Println("agent binary installed; restart and health-check before commit")
		return
	}

	cfg, _ := loadConfig(*configPath)
	if *server != "" {
		cfg.Server = strings.TrimRight(*server, "/")
	}
	if *token != "" {
		cfg.EnrollmentToken = *token
	}
	if *allowInsecureHTTP {
		cfg.AllowInsecureHTTP = true
	}
	if cfg.ReleaseRepo == "" {
		cfg.ReleaseRepo = *repoFlag
	}
	if cfg.Server == "" {
		fatalf("missing server URL")
	}
	cfg.Server = strings.TrimRight(cfg.Server, "/")
	if err := validateServerURL(cfg.Server, cfg.AllowInsecureHTTP); err != nil {
		fatalf("server URL: %v", err)
	}
	state := &ConfigState{cfg: cfg, path: *configPath}
	client := &http.Client{Timeout: 35 * time.Second}
	sampler := newSampler()
	if cfg.NodeID == "" || cfg.Secret == "" {
		if cfg.EnrollmentToken == "" {
			fatalf("agent is not enrolled and no enrollment token is configured")
		}
		var rr RegisterResponse
		if err := doJSON(client, "POST", cfg.Server+"/api/agent/register", "", RegisterRequest{Token: cfg.EnrollmentToken, System: sampler.sys}, &rr); err != nil {
			fatalf("registration failed: %v", err)
		}
		cfg.NodeID, cfg.Secret, cfg.EnrollmentToken = rr.NodeID, rr.Secret, ""
		if err := state.set(cfg); err != nil {
			fatalf("save config: %v", err)
		}
		fmt.Printf("NodeLume Agent enrolled as %s\n", cfg.NodeID)
	}
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	go heartbeatLoop(client, state, sampler)
	go commandLoop(client, state, sampler)
	<-done
}

func heartbeatLoop(client *http.Client, state *ConfigState, s *Sampler) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	firstCommit := true
	for {
		cfg := state.get()
		hb := s.Sample()
		var out HeartbeatResponse
		err := doJSON(client, "POST", cfg.Server+"/api/agent/heartbeat", auth(cfg), hb, &out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "heartbeat: %v\n", err)
		} else {
			// A newly installed Agent is only committed after it can heartbeat a
			// Server speaking the same protocol. Otherwise the privileged helper
			// keeps the previous binary and its watchdog rolls the update back.
			if firstCommit && out.ServerProtocol == protocolVersion {
				if _, er := helperCall(HelperRequest{Action: "agent_update_commit"}, 10*time.Second); er == nil {
					firstCommit = false
				}
			}
			if out.ServerURL != "" && out.ServerURL != cfg.Server && strings.HasPrefix(out.ServerURL, "https://") {
				if verifyEndpoint(out.ServerURL) {
					cfg.Server = strings.TrimRight(out.ServerURL, "/")
					if state.set(cfg) == nil {
						fmt.Fprintf(os.Stderr, "server endpoint migrated to %s; restarting agent\n", cfg.Server)
						os.Exit(0)
					}
				}
			}
		}
		<-ticker.C
	}
}
func verifyEndpoint(base string) bool {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(strings.TrimRight(base, "/") + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
func commandLoop(client *http.Client, state *ConfigState, s *Sampler) {
	for {
		cfg := state.get()
		req, _ := http.NewRequest("GET", cfg.Server+"/api/agent/commands?wait=25", nil)
		req.Header.Set("Authorization", "Bearer "+auth(cfg))
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.StatusCode == 204 {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != 200 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		var cmd AgentCommand
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cmd)
		resp.Body.Close()
		if err != nil {
			continue
		}
		res, restart := executeCommand(cmd, s, state.get())
		_ = doJSON(client, "POST", cfg.Server+"/api/agent/results", auth(cfg), res, nil)
		if restart && res.OK {
			time.Sleep(400 * time.Millisecond)
			os.Exit(0)
		}
	}
}

func executeCommand(cmd AgentCommand, s *Sampler, cfg Config) (AgentResult, bool) {
	r := AgentResult{RequestID: cmd.ID, Action: cmd.Action, OK: true}
	restart := false
	marshal := func(v any) {
		b, err := json.Marshal(v)
		if err != nil {
			r.OK = false
			r.Error = err.Error()
		} else {
			r.Data = b
		}
	}
	if cmd.Protocol != protocolVersion {
		r.OK = false
		r.Error = "protocol mismatch"
		return r, false
	}
	if time.Now().Unix()-cmd.Timestamp > 120 {
		r.OK = false
		r.Error = "stale command"
		return r, false
	}
	switch cmd.Action {
	case "agent_ping":
		marshal(map[string]any{"pong": true, "version": agentVersion, "protocol": protocolVersion})
	case "agent_self_check":
		marshal(map[string]any{"status": "ok", "version": agentVersion, "protocol_version": protocolVersion, "helper_socket": helperSocketPath()})
	case "system_info":
		marshal(s.sys)
	case "process_list":
		list, err := s.processList(true)
		if err != nil {
			r.OK = false
			r.Error = err.Error()
		} else {
			marshal(list)
		}
	case "process_info":
		var out ProcessDetail
		if err := helperJSON(HelperRequest{Action: "process_info", PID: cmd.PID}, &out, 10*time.Second); err != nil {
			r.OK = false
			r.Error = err.Error()
		} else {
			out.CPU = s.currentProcCPU(cmd.PID)
			marshal(out)
		}
	case "process_terminate", "process_kill", "process_restart", "service_stop", "service_restart":
		var out any = map[string]any{}
		if err := helperJSON(HelperRequest{Action: cmd.Action, PID: cmd.PID}, &out, 20*time.Second); err != nil {
			r.OK = false
			r.Error = err.Error()
		} else {
			marshal(out)
		}
	case "stopped_list":
		var out []StoppedRecord
		if err := helperJSON(HelperRequest{Action: "stopped_list"}, &out, 10*time.Second); err != nil {
			r.OK = false
			r.Error = err.Error()
		} else {
			marshal(out)
		}
	case "process_start_saved":
		var out any = map[string]any{}
		if err := helperJSON(HelperRequest{Action: "process_start_saved", RestartID: cmd.RestartID}, &out, 15*time.Second); err != nil {
			r.OK = false
			r.Error = err.Error()
		} else {
			marshal(out)
		}
	case "disk_info":
		marshal(readDisks())
	case "network_info":
		marshal(readNetworkInterfaces())
	case "listening_ports":
		marshal(readListeningPorts())
	case "sensor_info":
		marshal(map[string]any{"temperature": readTemperature()})
	case "agent_upgrade":
		target := strings.TrimPrefix(strings.TrimSpace(cmd.Version), "v")
		if !validVersion(target) {
			r.OK = false
			r.Error = "invalid target version"
			break
		}
		if compareVersion(agentVersion, target) >= 0 {
			marshal(map[string]string{"version": agentVersion, "status": "already_current"})
			break
		}
		var out any = map[string]any{}
		if err := helperJSON(HelperRequest{Action: "agent_upgrade", Version: target, Repo: cfg.ReleaseRepo}, &out, 40*time.Second); err != nil {
			r.OK = false
			r.Error = err.Error()
		} else {
			marshal(out)
			restart = true
		}
	default:
		r.OK = false
		r.Error = "unsupported action"
	}
	return r, restart
}

type HelperRequest struct {
	Action    string `json:"action"`
	PID       int    `json:"pid,omitempty"`
	RestartID string `json:"restart_id,omitempty"`
	Unit      string `json:"unit,omitempty"`
	Version   string `json:"version,omitempty"`
	Repo      string `json:"repo,omitempty"`
}
type HelperResponse struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

func helperCall(req HelperRequest, timeout time.Duration) (HelperResponse, error) {
	c, err := net.DialTimeout("unix", helperSocketPath(), 2*time.Second)
	if err != nil {
		return HelperResponse{}, fmt.Errorf("privileged helper unavailable: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err = json.NewEncoder(c).Encode(req); err != nil {
		return HelperResponse{}, err
	}
	var resp HelperResponse
	if err = json.NewDecoder(io.LimitReader(c, 4<<20)).Decode(&resp); err != nil {
		return resp, err
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
func helperJSON(req HelperRequest, out any, timeout time.Duration) error {
	resp, err := helperCall(req, timeout)
	if err != nil {
		return err
	}
	if out != nil && len(resp.Data) > 0 {
		return json.Unmarshal(resp.Data, out)
	}
	return nil
}

func validateServerURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("invalid server URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" {
		return errors.New("only https:// is allowed")
	}
	h := u.Hostname()
	if h == "localhost" {
		return nil
	}
	ip := net.ParseIP(h)
	if ip != nil && ip.IsLoopback() {
		return nil
	}
	if allowInsecure {
		return nil
	}
	return errors.New("plain HTTP to a remote Server is disabled; configure HTTPS first")
}

func auth(c Config) string { return c.NodeID + "." + c.Secret }
func doJSON(client *http.Client, method, url, authorization string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", "Bearer "+authorization)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func loadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}
func saveConfig(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, "nodelume-agent: "+f+"\n", a...); os.Exit(1) }
func fileExists(p string) bool  { _, err := os.Stat(p); return err == nil }
func validRepo(repo string) bool {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, p := range parts {
		for _, r := range p {
			if !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return false
			}
		}
	}
	return true
}
func validVersion(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	ps := strings.Split(v, ".")
	if len(ps) != 3 {
		return false
	}
	for _, p := range ps {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return false
		}
	}
	return true
}
func compareVersion(a, b string) int {
	parse := func(v string) [3]int {
		var o [3]int
		ps := strings.Split(strings.TrimPrefix(v, "v"), ".")
		for i := 0; i < len(ps) && i < 3; i++ {
			o[i], _ = strconv.Atoi(ps[i])
		}
		return o
	}
	x, y := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}
