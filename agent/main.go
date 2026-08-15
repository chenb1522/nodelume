package main

import (
	"bytes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

var agentVersion = "1.0.2"
var releaseRepo = "chenb1522/nodelume"

const protocolVersion = 1
const helperSocket = "/run/nodelume-agent-helper.sock"
const stoppedPath = "/var/lib/nodelume-agent-helper/stopped.json"
const pendingUpdatePath = "/var/lib/nodelume-agent-helper/update/pending.json"

type Config struct {
	Server            string `json:"server"`
	EnrollmentToken   string `json:"enrollment_token,omitempty"`
	NodeID            string `json:"node_id,omitempty"`
	Secret            string `json:"secret,omitempty"`
	ReleaseRepo       string `json:"release_repo,omitempty"`
	Name              string `json:"name,omitempty"`
	ReportIntervalSec int    `json:"report_interval_sec,omitempty"`
	ConfigVersion     int    `json:"config_version,omitempty"`
	LogLevel          string `json:"log_level,omitempty"`
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
	Time              int64            `json:"time"`
	CPU               float64          `json:"cpu"`
	CPUFreqMHz        float64          `json:"cpu_freq_mhz,omitempty"`
	Memory            float64          `json:"memory"`
	MemoryUsed        uint64           `json:"memory_used"`
	MemoryAvail       uint64           `json:"memory_available"`
	SwapUsed          uint64           `json:"swap_used,omitempty"`
	SwapTotal         uint64           `json:"swap_total,omitempty"`
	Disk              float64          `json:"disk"`
	DiskUsed          uint64           `json:"disk_used"`
	DiskTotal         uint64           `json:"disk_total"`
	Temperature       *float64         `json:"temperature,omitempty"`
	Load1             float64          `json:"load1"`
	Load5             float64          `json:"load5"`
	Load15            float64          `json:"load15"`
	NetIn             float64          `json:"net_in"`
	NetOut            float64          `json:"net_out"`
	Uptime            float64          `json:"uptime"`
	Processes         int              `json:"processes"`
	ReportIntervalSec int              `json:"report_interval_sec,omitempty"`
	TopCPU            []ProcessSummary `json:"top_cpu"`
	TopMemory         []ProcessSummary `json:"top_memory"`
	System            SystemInfo       `json:"system"`
	Self              SelfStats        `json:"self,omitempty"`
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
	Interval  int    `json:"interval,omitempty"`
}
type AgentResult struct {
	RequestID string          `json:"request_id"`
	Action    string          `json:"action"`
	OK        bool            `json:"ok"`
	Error     string          `json:"error,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}
type RegisterRequest struct {
	Token        string     `json:"token"`
	Name         string     `json:"name,omitempty"`
	EnrollmentID string     `json:"enrollment_id,omitempty"`
	AgentVersion string     `json:"agent_version,omitempty"`
	Protocol     int        `json:"protocol"`
	System       SystemInfo `json:"system"`
}
type RegisterResponse struct {
	NodeID            string `json:"node_id"`
	NodeName          string `json:"node_name"`
	Secret            string `json:"secret"`
	ServerVersion     string `json:"server_version"`
	ProtocolMin       int    `json:"protocol_min"`
	ProtocolMax       int    `json:"protocol_max"`
	ReportIntervalSec int    `json:"report_interval_sec"`
}
type HeartbeatResponse struct {
	OK                  bool   `json:"ok"`
	NodeName            string `json:"node_name"`
	ServerURL           string `json:"server_url"`
	ServerProtocol      int    `json:"server_protocol"`
	ReportIntervalSec   int    `json:"report_interval_sec"`
	HeartbeatExtensions bool   `json:"heartbeat_extensions"`
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
	if handled, code := maybeRunAgentSubcommand(os.Args[1:]); handled {
		os.Exit(code)
	}
	configPath := flag.String("config", "/var/lib/nodelume-agent/agent.json", "config file")
	server := flag.String("server", "", "server URL")
	token := flag.String("token", "", "one-time enrollment token")
	name := flag.String("name", "", "node display name used during enrollment")
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
			fatalf("发布文件校验失败: %v", err)
		}
		fmt.Println("发布文件校验通过")
		return
	}
	if *selfCheck {
		fmt.Printf("NodeLume Agent v%s self-check OK\n", agentVersion)
		return
	}
	if *helper {
		if err := runHelper(*helperSock); err != nil {
			fatalf("特权 Helper 启动失败: %v", err)
		}
		return
	}
	if *rollback {
		if err := rollbackAgentBinary(); err != nil {
			fatalf("回滚失败: %v", err)
		}
		fmt.Println("回滚完成")
		return
	}
	if *commit {
		if err := commitAgentUpdate(); err != nil {
			fatalf("提交更新状态失败: %v", err)
		}
		fmt.Println("更新状态已提交")
		return
	}
	if *upgradeSelf != "" {
		if os.Geteuid() != 0 {
			fatalf("自更新必须使用 root 权限运行")
		}
		if err := performAgentUpgrade(strings.TrimPrefix(*upgradeSelf, "v"), *repoFlag, *pubKey, false); err != nil {
			fatalf("更新失败: %v", err)
		}
		fmt.Println("Agent 二进制已安装；请重启并通过健康检查后提交更新状态")
		return
	}

	cfg, cfgErr := loadConfig(*configPath)
	if cfgErr != nil && !errors.Is(cfgErr, os.ErrNotExist) {
		fatalf("读取配置失败: %v", cfgErr)
	}
	if *server != "" {
		cfg.Server = strings.TrimRight(*server, "/")
	}
	if *token != "" {
		cfg.EnrollmentToken = *token
	}
	if *name != "" {
		cfg.Name = strings.TrimSpace(*name)
	}
	if cfg.ConfigVersion == 0 {
		cfg.ConfigVersion = 2
	}
	if cfg.ReportIntervalSec == 0 {
		cfg.ReportIntervalSec = 2
	}
	if cfg.ReleaseRepo == "" {
		cfg.ReleaseRepo = *repoFlag
	}
	if cfg.Server == "" {
		fmt.Println("NodeLume Agent: 未绑定 Server，使用 nlm agent bind -s <SERVER> -t <TOKEN> 完成绑定。")
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
		<-done
		return
	}
	cfg.Server = strings.TrimRight(cfg.Server, "/")
	if err := validateServerURL(cfg.Server); err != nil {
		fatalf("Server 地址无效: %v", err)
	}
	state := &ConfigState{cfg: cfg, path: *configPath}
	client := agentHTTPClient(35 * time.Second)
	sampler := newSampler()
	if cfg.NodeID == "" || cfg.Secret == "" {
		if cfg.EnrollmentToken == "" {
			fatalf("Agent 尚未接入，且未配置接入 Token")
		}
		var rr RegisterResponse
		if err := doJSON(client, "POST", cfg.Server+"/api/agent/register", "", RegisterRequest{Token: cfg.EnrollmentToken, Name: cfg.Name, EnrollmentID: enrollmentID(cfg), AgentVersion: "v" + agentVersion, Protocol: protocolVersion, System: sampler.sys}, &rr); err != nil {
			fatalf("Agent 接入失败: %v", err)
		}
		cfg.NodeID, cfg.Secret, cfg.EnrollmentToken = rr.NodeID, rr.Secret, ""
		if strings.TrimSpace(rr.NodeName) != "" {
			cfg.Name = strings.TrimSpace(rr.NodeName)
		}
		if rr.ReportIntervalSec > 0 {
			cfg.ReportIntervalSec = rr.ReportIntervalSec
		}
		if err := state.set(cfg); err != nil {
			fatalf("保存 Agent 配置失败: %v", err)
		}
		fmt.Printf("NodeLume Agent enrolled as %s\n", cfg.NodeID)
	}
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	intervalWake := make(chan struct{}, 1)

	go heartbeatLoop(client, state, sampler, intervalWake)
	go commandLoop(client, state, sampler, intervalWake)
	<-done
}

func heartbeatLoop(client *http.Client, state *ConfigState, s *Sampler, intervalWake <-chan struct{}) {
	firstCommit := true
	heartbeatExtensions := false
	for {
		cfg := state.get()
		hb := s.Sample()
		hb.ReportIntervalSec = cfg.ReportIntervalSec
		hb.Self = agentSelfStats(state.path)
		writeAgentRuntimeStatus(state.path, hb.Self, cfg)
		wireHB := heartbeatForServer(hb, heartbeatExtensions)
		var out HeartbeatResponse
		err := doJSON(client, "POST", cfg.Server+"/api/agent/heartbeat", auth(cfg), wireHB, &out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "心跳失败：%v\n", err)
		} else {
			heartbeatExtensions = out.HeartbeatExtensions
			if firstCommit && out.ServerProtocol == protocolVersion {
				if _, er := helperCall(HelperRequest{Action: "agent_update_commit"}, 10*time.Second); er == nil {
					firstCommit = false
				}
			}
			configChanged := false
			if name := strings.TrimSpace(out.NodeName); name != "" && name != cfg.Name {
				cfg.Name = name
				configChanged = true
			}
			if out.ReportIntervalSec == 2 || out.ReportIntervalSec == 5 || out.ReportIntervalSec == 10 || out.ReportIntervalSec == 30 || out.ReportIntervalSec == 60 {
				if out.ReportIntervalSec != cfg.ReportIntervalSec {
					cfg.ReportIntervalSec = out.ReportIntervalSec
					configChanged = true
				}
			}
			if configChanged {
				if state.set(cfg) == nil {
					writeAgentRuntimeStatus(state.path, hb.Self, cfg)
				}
			}
			if out.ServerURL != "" && out.ServerURL != cfg.Server {
				next := state.get()
				next.Server = strings.TrimRight(out.ServerURL, "/")
				if validateServerURL(next.Server) == nil && testAuthenticatedServer(next.Server, next) == nil {
					if state.set(next) == nil {
						fmt.Fprintf(os.Stderr, "Server 地址已切换至 %s\n", next.Server)
					}
				}
			}
		}
		interval := state.get().ReportIntervalSec
		if interval != 2 && interval != 5 && interval != 10 && interval != 30 && interval != 60 {
			interval = 2
		}
		timer := time.NewTimer(time.Duration(interval) * time.Second)
		select {
		case <-timer.C:
		case <-intervalWake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}
}
func heartbeatForServer(hb Heartbeat, extensions bool) Heartbeat {
	if extensions {
		return hb
	}
	// Protocol 1 servers prior to heartbeat extensions reject unknown JSON
	// fields. Start with the legacy payload and enable additive metrics only
	// after the Server explicitly advertises support.
	hb.CPUFreqMHz = 0
	hb.SwapUsed = 0
	hb.SwapTotal = 0
	hb.ReportIntervalSec = 0
	return hb
}

func verifyEndpoint(base string) bool {
	c := agentHTTPClient(5 * time.Second)
	resp, err := c.Get(strings.TrimRight(base, "/") + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
func commandLoop(client *http.Client, state *ConfigState, s *Sampler, intervalWake chan<- struct{}) {

	for {
		cfg := state.get()
		req, _ := http.NewRequest("GET", cfg.Server+"/api/agent/commands?wait=25", nil)
		signRequest(req, nil, cfg)
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
		res, restart := executeCommand(cmd, s, state)
		_ = doJSON(client, "POST", cfg.Server+"/api/agent/results", auth(cfg), res, nil)

		// Wake the heartbeat only after the command result has been delivered.
		// This lets the Server commit its desired interval before the immediate
		// heartbeat asks for configuration again.
		if cmd.Action == "set_report_interval" && res.OK {
			select {
			case intervalWake <- struct{}{}:
			default:
			}
		}

		if restart && res.OK {
			time.Sleep(400 * time.Millisecond)
			os.Exit(0)
		}
	}
}

func executeCommand(cmd AgentCommand, s *Sampler, state *ConfigState) (AgentResult, bool) {
	cfg := state.get()
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
	case "set_report_interval":
		if cmd.Interval != 2 && cmd.Interval != 5 && cmd.Interval != 10 && cmd.Interval != 30 && cmd.Interval != 60 {
			r.OK = false
			r.Error = "unsupported report interval"
			break
		}
		cfg.ReportIntervalSec = cmd.Interval
		if err := state.set(cfg); err != nil {
			r.OK = false
			r.Error = err.Error()
			break
		}
		marshal(map[string]any{"report_interval_sec": cmd.Interval})
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
		if err := helperJSON(HelperRequest{Action: "agent_upgrade", Version: target, Repo: cfg.ReleaseRepo}, &out, 120*time.Second); err != nil {
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
		return HelperResponse{}, fmt.Errorf("特权 Helper 不可用: %w", err)
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

func validateServerURL(raw string, _ ...bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("Server 地址无效")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("Server 地址仅支持 http:// 或 https://")
	}
	if u.Scheme == "http" {
		fmt.Fprintln(os.Stderr, "[WARN] 当前使用 HTTP，首次注册和通信未加密。")
	}
	return nil
}

func enrollmentID(c Config) string {
	h := sha256.Sum256([]byte(c.Server + "|" + c.Name + "|" + hostnameSafe()))
	return hex.EncodeToString(h[:16])
}
func hostnameSafe() string { h, _ := os.Hostname(); return h }

func signRequest(req *http.Request, body []byte, c Config) {
	if c.NodeID == "" || c.Secret == "" {
		return
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonceBytes := make([]byte, 12)
	_, _ = cryptorand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)
	bh := sha256.Sum256(body)
	msg := req.Method + "\n" + req.URL.RequestURI() + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(bh[:])
	m := hmac.New(sha256.New, []byte(c.Secret))
	m.Write([]byte(msg))
	req.Header.Set("X-Node-ID", c.NodeID)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", hex.EncodeToString(m.Sum(nil)))
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
		parts := strings.SplitN(authorization, ".", 2)
		if len(parts) == 2 {
			signRequest(req, bodyBytes(in), Config{NodeID: parts[0], Secret: parts[1]})
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIError(resp)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func bodyBytes(v any) []byte {
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	return b
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
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	// Use the config directory owner for the replacement file. The standard
	// directory is owned by nodelume-agent; this also repairs a config that a
	// previous root CLI rewrite accidentally left as root:root 0600.
	targetUID, targetGID := -1, -1
	if st, err := os.Stat(dir); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			targetUID, targetGID = int(sys.Uid), int(sys.Gid)
		}
	}

	f, err := os.CreateTemp(dir, ".agent.json.tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if err = f.Chmod(0600); err != nil {
		cleanup()
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if err != nil {
		cleanup()
		return err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if targetUID >= 0 && targetGID >= 0 {
		if st, er := os.Stat(tmp); er == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && (int(sys.Uid) != targetUID || int(sys.Gid) != targetGID) {
				if er = os.Chown(tmp, targetUID, targetGID); er != nil {
					_ = os.Remove(tmp)
					return er
				}
			}
		}
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, er := os.Open(dir); er == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
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
