package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var serverVersion = "1.0.1"
var releaseRepo = "chenb1522/nodelume"

const protocolVersion = 1
const historyCapacity = 720

//go:embed web/*
var webFS embed.FS

type PasswordRecord struct{ Salt, Hash string }

type Settings struct {
	Listen            string   `json:"listen,omitempty"`
	AdminPath         string   `json:"admin_path"`
	Domain            string   `json:"domain"`
	HTTPSMode         string   `json:"https_mode"`                   // off | proxy | builtin
	CertificateSource string   `json:"certificate_source,omitempty"` // acme | manual
	TrustedProxies    []string `json:"trusted_proxies"`
	ReleaseRepo       string   `json:"release_repo"`
	LogRetentionDays  int      `json:"log_retention_days"`
	LogMaxMiB         int      `json:"log_max_mib"`
	ConfigVersion     int      `json:"config_version"`
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

type PersistNode struct {
	ID                      string     `json:"id"`
	Name                    string     `json:"name"`
	Group                   string     `json:"group,omitempty"`
	Note                    string     `json:"note,omitempty"`
	ReportIntervalSec       int        `json:"report_interval_sec,omitempty"`
	SecretHash              string     `json:"secret_hash,omitempty"`  // legacy v1.0.0 bearer auth
	AgentSecret             string     `json:"agent_secret,omitempty"` // v1.0.1 HMAC key; state file is mode 0600
	PreviousAgentSecret     string     `json:"previous_agent_secret,omitempty"`
	PreviousSecretExpiresAt int64      `json:"previous_secret_expires_at,omitempty"`
	Registered              bool       `json:"registered"`
	CreatedAt               int64      `json:"created_at"`
	System                  SystemInfo `json:"system"`
}

type EnrollmentReceipt struct {
	NodeID    string `json:"node_id"`
	Secret    string `json:"secret"`
	ExpiresAt int64  `json:"expires_at"`
}

type Enrollment struct {
	NodeID    string `json:"node_id,omitempty"`
	Name      string `json:"name,omitempty"`
	ExpiresAt int64  `json:"expires_at"`
	Reusable  bool   `json:"reusable,omitempty"`
	Joined    int    `json:"joined,omitempty"`
}

type AuditEntry struct {
	Time   int64  `json:"time"`
	IP     string `json:"ip,omitempty"`
	Action string `json:"action"`
	Node   string `json:"node,omitempty"`
	Detail string `json:"detail,omitempty"`
	Result string `json:"result"`
}

type PersistedState struct {
	Password           PasswordRecord               `json:"password"`
	Settings           Settings                     `json:"settings"`
	Nodes              map[string]*PersistNode      `json:"nodes"`
	Enrollments        map[string]Enrollment        `json:"enrollments"`
	EnrollmentReceipts map[string]EnrollmentReceipt `json:"enrollment_receipts,omitempty"`
	Audit              []AuditEntry                 `json:"audit,omitempty"`
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
	ID        string `json:"id"`
	Name      string `json:"name"`
	Launch    string `json:"launch"`
	Service   string `json:"service,omitempty"`
	StoppedAt int64  `json:"stopped_at"`
	CanStart  bool   `json:"can_start"`
	Note      string `json:"note,omitempty"`
}

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
	Self        SelfStats        `json:"self,omitempty"`
}

type MetricPoint struct {
	T                                             int64
	CPU, Memory, Disk, Temp, Load1, NetIn, NetOut float32
	TempValid                                     bool
}
type HistoryPoint struct {
	T           int64    `json:"t"`
	CPU         float32  `json:"cpu"`
	Memory      float32  `json:"memory"`
	Disk        float32  `json:"disk"`
	Temperature *float32 `json:"temperature,omitempty"`
	Load1       float32  `json:"load1"`
	NetIn       float32  `json:"net_in"`
	NetOut      float32  `json:"net_out"`
}

type Ring struct {
	points      []MetricPoint
	next, count int
}

func NewRing(n int) *Ring { return &Ring{points: make([]MetricPoint, n)} }
func (r *Ring) Add(p MetricPoint) {
	if len(r.points) == 0 {
		return
	}
	r.points[r.next] = p
	r.next = (r.next + 1) % len(r.points)
	if r.count < len(r.points) {
		r.count++
	}
}
func (r *Ring) all() []MetricPoint {
	out := make([]MetricPoint, 0, r.count)
	start := r.next - r.count
	if start < 0 {
		start += len(r.points)
	}
	for i := 0; i < r.count; i++ {
		out = append(out, r.points[(start+i)%len(r.points)])
	}
	return out
}
func (r *Ring) Since(cut int64) []HistoryPoint {
	out := []HistoryPoint{}
	for _, p := range r.all() {
		if p.T < cut {
			continue
		}
		h := HistoryPoint{T: p.T, CPU: p.CPU, Memory: p.Memory, Disk: p.Disk, Load1: p.Load1, NetIn: p.NetIn, NetOut: p.NetOut}
		if p.TempValid {
			v := p.Temp
			h.Temperature = &v
		}
		out = append(out, h)
	}
	return out
}
func (r *Ring) Prune(cut int64) {
	old := r.all()
	r.next = 0
	r.count = 0
	for _, p := range old {
		if p.T >= cut {
			r.Add(p)
		}
	}
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

type RuntimeNode struct {
	LastSeen    time.Time
	Latest      Heartbeat
	History     *Ring
	LastHistory time.Time
	Commands    chan AgentCommand
	pendingMu   sync.Mutex
	Pending     map[string]chan AgentResult
}

func newRuntimeNode() *RuntimeNode {
	return &RuntimeNode{History: NewRing(historyCapacity), Commands: make(chan AgentCommand, 16), Pending: map[string]chan AgentResult{}}
}

type Session struct {
	CSRF    string
	Expires time.Time
}
type LoginFail struct {
	Count  int
	Banned bool
}

type App struct {
	mu                                                                                                sync.RWMutex
	state                                                                                             PersistedState
	runtime                                                                                           map[string]*RuntimeNode
	sessions                                                                                          map[string]Session
	loginFails                                                                                        map[string]LoginFail
	dataPath, acmeDir, updateRequestPath, updateStatusPath, listen, activeListen, configuredPublicURL string
	handler                                                                                           http.Handler
	httpsMu                                                                                           sync.Mutex
	httpsRuntime                                                                                      *HTTPSRuntime
	noncesMu                                                                                          sync.Mutex
	nonces                                                                                            map[string]int64
	logWriter                                                                                         *logWriter
	httpRX, httpTX                                                                                    atomic.Uint64
	enrollRateMu                                                                                      sync.Mutex
	enrollRate                                                                                        map[string][]int64
	selfMu                                                                                            sync.Mutex
	selfCache                                                                                         SelfStats
	selfCacheAt                                                                                       time.Time
	selfPrevRX                                                                                        uint64
	selfPrevTX                                                                                        uint64
	selfPrevAt                                                                                        time.Time
}

func main() {
	listen := flag.String("listen", envOr("NODELUME_LISTEN", "127.0.0.1:8080"), "internal listen address")
	data := flag.String("data", envOr("NODELUME_DATA", "/var/lib/nodelume/state.json"), "state file")
	acmeDir := flag.String("acme-dir", envOr("NODELUME_ACME_DIR", "/var/lib/nodelume/acme"), "ACME data directory")
	publicURL := flag.String("public-url", envOr("NODELUME_PUBLIC_URL", ""), "fallback public URL")
	updateRequest := flag.String("update-request", envOr("NODELUME_UPDATE_REQUEST", "/var/lib/nodelume/update/request.json"), "server update request")
	updateStatus := flag.String("update-status", envOr("NODELUME_UPDATE_STATUS", "/var/lib/nodelume/update/status.json"), "server update status")
	showVersion := flag.Bool("version", false, "print version")
	pickPort := flag.Bool("pick-port", false, "print an unused TCP port and exit")
	selfCheck := flag.Bool("self-check", false, "validate binary and exit")
	verifyFile := flag.String("verify-file", "", "verify a release binary")
	checksums := flag.String("checksums", "", "checksums.txt path")
	signature := flag.String("signature", "", "checksums.sig path")
	pubKey := flag.String("public-key", envOr("NODELUME_RELEASE_PUBLIC_KEY", "/etc/nodelume/release.pub"), "Ed25519 public key file")
	repoFlag := flag.String("repo", envOr("NODELUME_RELEASE_REPO", releaseRepo), "GitHub release repository")
	flag.Parse()
	if validRepo(*repoFlag) {
		releaseRepo = *repoFlag
	}
	if *showVersion {
		fmt.Printf("NodeLume Server v%s (protocol %d)\n", serverVersion, protocolVersion)
		return
	}
	if *pickPort {
		ln, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer ln.Close()
		_, p, _ := net.SplitHostPort(ln.Addr().String())
		fmt.Println(p)
		return
	}
	if *selfCheck {
		fmt.Printf("NodeLume Server v%s self-check OK\n", serverVersion)
		return
	}
	if *verifyFile != "" {
		if err := verifyReleaseFile(*verifyFile, *checksums, *signature, *pubKey); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("release verification OK")
		return
	}

	a := &App{dataPath: *data, acmeDir: *acmeDir, updateRequestPath: *updateRequest, updateStatusPath: *updateStatus, listen: *listen, activeListen: *listen, configuredPublicURL: strings.TrimRight(*publicURL, "/"), runtime: map[string]*RuntimeNode{}, sessions: map[string]Session{}, loginFails: map[string]LoginFail{}, nonces: map[string]int64{}, enrollRate: map[string][]int64{}}
	if err := a.load(); err != nil {
		log.Fatalf("load state: %v", err)
	}
	if a.state.Settings.Listen != "" {
		a.listen = a.state.Settings.Listen
	} else {
		a.state.Settings.Listen = a.listen
		a.mu.Lock()
		_ = a.saveLocked()
		a.mu.Unlock()
	}
	a.activeListen = a.listen
	logWriter, logErr := newLogWriter(filepath.Join(filepath.Dir(a.dataPath), "logs"), a.state.Settings.LogRetentionDays, a.state.Settings.LogMaxMiB)
	if logErr == nil {
		a.logWriter = logWriter
		defer logWriter.Close()
		log.SetOutput(logWriter)
	}
	mux := http.NewServeMux()
	a.routes(mux)
	a.handler = securityHeaders(a.measureHTTP(a.recoverer(mux)))
	srv := &http.Server{Addr: a.listen, Handler: a.handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 65 * time.Second, MaxHeaderBytes: 1 << 20}
	go a.maintenance()
	log.Printf("NodeLume Server v%s listening on %s", serverVersion, a.listen)
	ln, err := net.Listen("tcp", a.listen)
	if err != nil {
		log.Fatalf("PORT_IN_USE: listen %s: %v", a.listen, err)
	}
	a.mu.RLock()
	mode, domain := a.state.Settings.HTTPSMode, a.state.Settings.Domain
	a.mu.RUnlock()
	var serveErr error
	if mode == "builtin" && domain != "" {
		certPath, keyPath := a.certPaths(domain)
		if _, err := loadTLSCertificate(certPath, keyPath); err == nil {
			log.Printf("NodeLume built-in HTTPS enabled for %s on %s", domain, a.listen)
			serveErr = srv.ServeTLS(ln, certPath, keyPath)
		} else {
			log.Printf("certificate unavailable for %s; keeping HTTP listener usable: %v", domain, err)
			serveErr = srv.Serve(ln)
		}
	} else {
		serveErr = srv.Serve(ln)
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		log.Fatal(serveErr)
	}
}

func (a *App) routes(m *http.ServeMux) {
	m.HandleFunc("GET /assets/{name}", a.serveAsset)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "server_version": serverVersion, "protocol_version": protocolVersion})
	})
	m.HandleFunc("GET /api/setup/status", a.setupStatus)
	m.HandleFunc("POST /api/setup", a.setupPassword)
	m.HandleFunc("POST /api/login", a.login)
	m.HandleFunc("POST /api/logout", a.requireAuthCSRF(a.logout))
	m.HandleFunc("GET /api/session", a.requireAuth(a.sessionInfo))
	m.HandleFunc("GET /api/settings", a.requireAuth(a.getSettings))
	m.HandleFunc("GET /api/self/status", a.requireAuth(a.selfStatus))
	m.HandleFunc("GET /api/settings/listen", a.requireAuth(a.getListenSettings))
	m.HandleFunc("PATCH /api/settings/listen", a.requireAuthCSRF(a.saveListenSettings))
	m.HandleFunc("POST /api/server/restart", a.requireAuthCSRF(a.restartServer))
	m.HandleFunc("POST /api/settings/security", a.requireAuthCSRF(a.saveSecuritySettings))
	m.HandleFunc("POST /api/settings/password", a.requireAuthCSRF(a.changePassword))
	m.HandleFunc("POST /api/settings/https/check", a.requireAuthCSRF(a.checkHTTPSSettings))
	m.HandleFunc("POST /api/settings/https/apply", a.requireAuthCSRF(a.applyHTTPSSettings))
	m.HandleFunc("POST /api/settings/certificate/check", a.requireAuthCSRF(a.checkCertificate))
	m.HandleFunc("POST /api/settings/certificate/import", a.requireAuthCSRF(a.importCertificate))
	m.HandleFunc("POST /api/settings/logs", a.requireAuthCSRF(a.saveLogSettings))
	m.HandleFunc("GET /api/logs/runtime", a.requireAuth(a.runtimeLogs))
	m.HandleFunc("GET /api/logs/runtime/stream", a.requireAuth(a.runtimeLogStream))
	m.HandleFunc("DELETE /api/logs/runtime", a.requireAuthCSRF(a.clearRuntimeLogs))
	m.HandleFunc("GET /api/enrollment/common", a.requireAuth(a.getCommonEnrollment))
	m.HandleFunc("POST /api/enrollment/common", a.requireAuthCSRF(a.setCommonEnrollment))
	m.HandleFunc("DELETE /api/enrollment/common", a.requireAuthCSRF(a.revokeCommonEnrollment))
	m.HandleFunc("GET /api/audit", a.requireAuth(a.auditLog))
	m.HandleFunc("GET /api/nodes", a.requireAuth(a.listNodes))
	m.HandleFunc("POST /api/nodes", a.requireAuthCSRF(a.createNode))
	m.HandleFunc("DELETE /api/nodes/{id}", a.requireAuthCSRF(a.deleteNode))
	m.HandleFunc("PATCH /api/nodes/{id}", a.requireAuthCSRF(a.editNode))
	m.HandleFunc("POST /api/nodes/{id}/reenroll", a.requireAuthCSRF(a.reenrollNode))
	m.HandleFunc("GET /api/nodes/{id}/history", a.requireAuth(a.nodeHistory))
	m.HandleFunc("GET /api/nodes/{id}/processes", a.requireAuth(a.nodeProcesses))
	m.HandleFunc("GET /api/nodes/{id}/process/{pid}", a.requireAuth(a.nodeProcessInfo))
	m.HandleFunc("POST /api/nodes/{id}/process/{pid}/action", a.requireAuthCSRF(a.nodeProcessAction))
	m.HandleFunc("GET /api/nodes/{id}/stopped", a.requireAuth(a.nodeStopped))
	m.HandleFunc("POST /api/nodes/{id}/stopped/{rid}/start", a.requireAuthCSRF(a.nodeStartStopped))
	m.HandleFunc("GET /api/nodes/{id}/disks", a.requireAuth(a.nodeDisks))
	m.HandleFunc("POST /api/nodes/{id}/update", a.requireAuthCSRF(a.nodeUpdate))
	m.HandleFunc("GET /api/update/status", a.requireAuth(a.updateStatus))
	m.HandleFunc("POST /api/update/server", a.requireAuthCSRF(a.requestServerUpdate))
	m.HandleFunc("POST /api/agent/register", a.agentRegister)
	m.HandleFunc("POST /api/agent/heartbeat", a.agentHeartbeat)
	m.HandleFunc("GET /api/agent/commands", a.agentCommands)
	m.HandleFunc("POST /api/agent/results", a.agentResults)
	m.HandleFunc("GET /", a.serveIndex)
}

func (a *App) serveIndex(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	p := a.state.Settings.AdminPath
	setup := a.state.Password.Hash == ""
	a.mu.RUnlock()
	if p == "" {
		p = "/"
	}
	allowed := r.URL.Path == p
	if setup && r.URL.Path == "/" {
		allowed = true
	}
	if !allowed {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "UI unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}
func (a *App) serveAsset(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	if name == "." || name == "" {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if ct := mime.TypeByExtension(filepath.Ext(name)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "public,max-age=3600")
	w.Write(b)
}

func (a *App) load() error {
	b, err := os.ReadFile(a.dataPath)
	if errors.Is(err, os.ErrNotExist) {
		a.state = PersistedState{Settings: Settings{Listen: a.listen, AdminPath: "/", HTTPSMode: "off", ReleaseRepo: releaseRepo, LogRetentionDays: 7, LogMaxMiB: 50, ConfigVersion: 3}, Nodes: map[string]*PersistNode{}, Enrollments: map[string]Enrollment{}, EnrollmentReceipts: map[string]EnrollmentReceipt{}}
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &a.state); err != nil {
		return err
	}
	if a.state.Nodes == nil {
		a.state.Nodes = map[string]*PersistNode{}
	}
	if a.state.Enrollments == nil {
		a.state.Enrollments = map[string]Enrollment{}
	}
	if a.state.EnrollmentReceipts == nil {
		a.state.EnrollmentReceipts = map[string]EnrollmentReceipt{}
	}
	if a.state.Settings.AdminPath == "" {
		a.state.Settings.AdminPath = "/"
	}
	if a.state.Settings.ReleaseRepo == "" {
		a.state.Settings.ReleaseRepo = releaseRepo
	}
	if a.state.Settings.LogRetentionDays <= 0 {
		a.state.Settings.LogRetentionDays = 7
	}
	if a.state.Settings.LogMaxMiB <= 0 {
		a.state.Settings.LogMaxMiB = 50
	}
	if a.state.Settings.ConfigVersion == 0 {
		a.state.Settings.ConfigVersion = 3
	}
	for id := range a.state.Nodes {
		a.runtime[id] = newRuntimeNode()
	}
	return nil
}
func (a *App) saveLocked() error {
	b, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return atomicWrite(a.dataPath, b, 0600)
}
func (a *App) auditLocked(ip, action, node, detail, result string) {
	a.state.Audit = append([]AuditEntry{{Time: time.Now().Unix(), IP: ip, Action: action, Node: node, Detail: detail, Result: result}}, a.state.Audit...)
	if len(a.state.Audit) > 500 {
		a.state.Audit = a.state.Audit[:500]
	}
}
func (a *App) audit(ip, action, node, detail, result string) {
	a.mu.Lock()
	a.auditLocked(ip, action, node, detail, result)
	_ = a.saveLocked()
	a.mu.Unlock()
}

func (a *App) setupStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	required := a.state.Password.Hash == ""
	a.mu.RUnlock()
	writeJSON(w, 200, map[string]any{"required": required, "server_version": serverVersion})
}
func (a *App) setupPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in, 1<<14) {
		return
	}
	if len(in.Password) < 8 || len(in.Password) > 128 {
		jsonError(w, "password must be 8-128 characters", 400)
		return
	}
	ip := a.remoteIP(r)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Password.Hash != "" {
		jsonError(w, "already initialized", 409)
		return
	}
	a.state.Password = makePassword(in.Password)
	a.auditLocked(ip, "setup_password", "", "initial administrator password created", "success")
	if err := a.saveLocked(); err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func makePassword(pass string) PasswordRecord {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hash := passwordKey(pass, salt, 180000)
	return PasswordRecord{Salt: hex.EncodeToString(salt), Hash: hex.EncodeToString(hash)}
}
func checkPassword(pass string, rec PasswordRecord) bool {
	salt, err1 := hex.DecodeString(rec.Salt)
	want, err2 := hex.DecodeString(rec.Hash)
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := passwordKey(pass, salt, 180000)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := a.remoteIP(r)
	a.mu.RLock()
	f := a.loginFails[ip]
	initialized := a.state.Password.Hash != ""
	rec := a.state.Password
	a.mu.RUnlock()
	if !initialized {
		jsonError(w, "not initialized", 428)
		return
	}
	if f.Banned {
		jsonError(w, "source IP is banned until NodeLume Server restarts", 429)
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in, 1<<14) {
		return
	}
	if !checkPassword(in.Password, rec) {
		a.mu.Lock()
		f = a.loginFails[ip]
		f.Count++
		if f.Count >= 3 {
			f.Banned = true
		}
		a.loginFails[ip] = f
		a.auditLocked(ip, "login", "", fmt.Sprintf("failed attempt %d/3", minInt(f.Count, 3)), "failed")
		_ = a.saveLocked()
		a.mu.Unlock()
		time.Sleep(300 * time.Millisecond)
		if f.Banned {
			jsonError(w, "source IP is banned until server restart", 429)
		} else {
			jsonError(w, fmt.Sprintf("invalid password (%d/3)", f.Count), 401)
		}
		return
	}
	sid, csrf := randomToken(32), randomToken(24)
	a.mu.Lock()
	delete(a.loginFails, ip)
	a.sessions[sid] = Session{CSRF: csrf, Expires: time.Now().Add(12 * time.Hour)}
	a.auditLocked(ip, "login", "", "administrator login", "success")
	_ = a.saveLocked()
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "nodelume_session", Value: sid, Path: "/", HttpOnly: true, Secure: a.isHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	writeJSON(w, 200, map[string]any{"ok": true, "csrf": csrf})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	ip := a.remoteIP(r)
	if c, err := r.Cookie("nodelume_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.auditLocked(ip, "logout", "", "administrator logout", "success")
		_ = a.saveLocked()
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "nodelume_session", Value: "", Path: "/", HttpOnly: true, Secure: a.isHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) getSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie("nodelume_session")
	if err != nil {
		return Session{}, false
	}
	a.mu.RLock()
	s, ok := a.sessions[c.Value]
	a.mu.RUnlock()
	if !ok || time.Now().After(s.Expires) {
		return Session{}, false
	}
	return s, true
}
func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.getSession(r); !ok {
			jsonError(w, "unauthorized", 401)
			return
		}
		next(w, r)
	}
}
func (a *App) requireAuthCSRF(next http.HandlerFunc) http.HandlerFunc {
	return a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.getSession(r)
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
			jsonError(w, "bad csrf token", 403)
			return
		}
		next(w, r)
	})
}
func (a *App) sessionInfo(w http.ResponseWriter, r *http.Request) {
	s, _ := a.getSession(r)
	a.mu.RLock()
	settings := a.state.Settings
	a.mu.RUnlock()
	writeJSON(w, 200, map[string]any{"ok": true, "csrf": s.CSRF, "server_version": serverVersion, "protocol_version": protocolVersion, "settings": settings})
}

func (a *App) getSettings(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	s := a.state.Settings
	a.mu.RUnlock()
	cert := a.certificateStatus()
	writeJSON(w, 200, map[string]any{"settings": s, "certificate": cert, "server_version": serverVersion, "protocol_version": protocolVersion, "history": "1 hour / 5 seconds"})
}
func (a *App) saveSecuritySettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AdminPath string `json:"admin_path"`
	}
	if !decodeJSON(w, r, &in, 1<<16) {
		return
	}
	p := strings.TrimSpace(in.AdminPath)
	if p == "" {
		p = "/"
	}
	if p != "/" && !validAdminPath(p) {
		jsonError(w, "invalid admin path", 400)
		return
	}
	ip := a.remoteIP(r)
	a.mu.Lock()
	old := a.state.Settings.AdminPath
	a.state.Settings.AdminPath = p
	// Trusted proxy CIDRs are deliberately ignored in v1.0.1 normal configuration.
	// Only loopback reverse proxies are trusted by remoteIP()/isHTTPS().
	a.state.Settings.TrustedProxies = nil
	a.auditLocked(ip, "security_settings", "", fmt.Sprintf("admin path %s -> %s", old, p), "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "admin_path": p})
}
func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decodeJSON(w, r, &in, 1<<14) {
		return
	}
	if len(in.New) < 8 || len(in.New) > 128 {
		jsonError(w, "new password must be 8-128 characters", 400)
		return
	}
	ip := a.remoteIP(r)
	a.mu.Lock()
	if !checkPassword(in.Current, a.state.Password) {
		a.auditLocked(ip, "change_password", "", "current password rejected", "failed")
		_ = a.saveLocked()
		a.mu.Unlock()
		jsonError(w, "current password is incorrect", 403)
		return
	}
	a.state.Password = makePassword(in.New)
	a.sessions = map[string]Session{}
	a.auditLocked(ip, "change_password", "", "administrator password changed; sessions revoked", "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "nodelume_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) auditLog(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	out := append([]AuditEntry(nil), a.state.Audit...)
	a.mu.RUnlock()
	writeJSON(w, 200, out)
}

func (a *App) listNodes(w http.ResponseWriter, r *http.Request) {
	type V struct {
		ID                  string     `json:"id"`
		Name                string     `json:"name"`
		Group               string     `json:"group"`
		Note                string     `json:"note"`
		Status              string     `json:"status"`
		ReportIntervalSec   int        `json:"report_interval_sec"`
		OfflineThresholdSec int        `json:"offline_threshold_sec"`
		CreatedAt           int64      `json:"created_at"`
		LastSeen            int64      `json:"last_seen"`
		Latest              Heartbeat  `json:"latest"`
		System              SystemInfo `json:"system"`
	}
	a.mu.RLock()
	out := make([]V, 0, len(a.state.Nodes))
	for id, n := range a.state.Nodes {
		rt := a.runtime[id]
		status := "waiting"
		var last int64
		var latest Heartbeat
		if n.Registered {
			status = "offline"
		}
		if rt != nil {
			latest = rt.Latest
			if !rt.LastSeen.IsZero() {
				last = rt.LastSeen.Unix()
				if nodeIsOnline(n, rt) {
					status = "online"
				}
			}
		}
		out = append(out, V{ID: id, Name: n.Name, Group: n.Group, Note: n.Note, Status: status, ReportIntervalSec: n.ReportIntervalSec, OfflineThresholdSec: int(nodeOfflineThreshold(n) / time.Second), CreatedAt: n.CreatedAt, LastSeen: last, Latest: latest, System: n.System})
	}
	a.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	writeJSON(w, 200, out)
}
func (a *App) enrollmentBaseURL(r *http.Request) (string, error) {
	base := strings.TrimRight(a.baseURL(r), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("invalid public Server URL")
	}
	return base, nil
}

func (a *App) createNode(w http.ResponseWriter, r *http.Request) {
	if _, err := a.enrollmentBaseURL(r); err != nil {
		jsonError(w, err.Error(), 409)
		return
	}
	var in struct{ Name, Group string }
	if !decodeJSON(w, r, &in, 1<<16) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) > 80 {
		jsonError(w, "name must be at most 80 characters", 400)
		return
	}
	id := randomHex(12)
	if in.Name == "" {
		in.Name = "node-" + id[:6]
	}
	token := randomToken(32)
	th := hashString(token)
	ip := a.remoteIP(r)
	a.mu.Lock()
	a.state.Nodes[id] = &PersistNode{ID: id, Name: in.Name, Group: strings.TrimSpace(in.Group), CreatedAt: time.Now().Unix()}
	a.state.Enrollments[th] = Enrollment{NodeID: id, ExpiresAt: time.Now().Add(30 * time.Minute).Unix()}
	a.runtime[id] = newRuntimeNode()
	a.auditLocked(ip, "create_node", in.Name, "one-time enrollment created", "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "token": token, "install_command": a.agentInstallCommand(r, token), "expires_in": 1800})
}
func (a *App) reenrollNode(w http.ResponseWriter, r *http.Request) {
	if _, err := a.enrollmentBaseURL(r); err != nil {
		jsonError(w, err.Error(), 409)
		return
	}
	id := r.PathValue("id")
	token := randomToken(32)
	ip := a.remoteIP(r)
	a.mu.Lock()
	n := a.state.Nodes[id]
	if n == nil {
		a.mu.Unlock()
		jsonError(w, "node not found", 404)
		return
	}
	// Keep the current Agent credential valid until the new one successfully enrolls.
	for k, e := range a.state.Enrollments {
		if e.NodeID == id {
			delete(a.state.Enrollments, k)
		}
	}
	a.state.Enrollments[hashString(token)] = Enrollment{NodeID: id, ExpiresAt: time.Now().Add(30 * time.Minute).Unix()}
	a.auditLocked(ip, "reenroll_node", n.Name, "new one-time enrollment created; current credential remains valid until successful replacement", "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"token": token, "install_command": a.agentInstallCommand(r, token), "expires_in": 1800})
}
func (a *App) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ip := a.remoteIP(r)
	a.mu.Lock()
	n := a.state.Nodes[id]
	if n == nil {
		a.mu.Unlock()
		jsonError(w, "node not found", 404)
		return
	}
	delete(a.state.Nodes, id)
	delete(a.runtime, id)
	for k, e := range a.state.Enrollments {
		if e.NodeID == id {
			delete(a.state.Enrollments, k)
		}
	}
	a.auditLocked(ip, "delete_node", n.Name, "node and credential removed", "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) nodeHistory(w http.ResponseWriter, r *http.Request) {
	mins, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if mins != 1 && mins != 5 && mins != 10 && mins != 30 && mins != 60 {
		mins = 10
	}
	a.mu.RLock()
	rt := a.runtime[r.PathValue("id")]
	var out []HistoryPoint
	if rt != nil {
		out = rt.History.Since(time.Now().Add(-time.Duration(mins) * time.Minute).Unix())
	}
	a.mu.RUnlock()
	if rt == nil {
		jsonError(w, "node not found", 404)
		return
	}
	writeJSON(w, 200, out)
}
func (a *App) nodeProcesses(w http.ResponseWriter, r *http.Request) {
	a.commandJSON(w, r, "process_list", AgentCommand{}, 8*time.Second)
}
func (a *App) nodeProcessInfo(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(r.PathValue("pid"))
	if err != nil || pid < 1 {
		jsonError(w, "invalid pid", 400)
		return
	}
	a.commandJSON(w, r, "process_info", AgentCommand{PID: pid}, 8*time.Second)
}
func (a *App) nodeProcessAction(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(r.PathValue("pid"))
	if err != nil || pid <= 1 {
		jsonError(w, "invalid or protected pid", 400)
		return
	}
	var in struct {
		Action string `json:"action"`
	}
	if !decodeJSON(w, r, &in, 1<<12) {
		return
	}
	actionMap := map[string]string{"terminate": "process_terminate", "kill": "process_kill", "restart": "process_restart", "service_stop": "service_stop", "service_restart": "service_restart"}
	act := actionMap[in.Action]
	if act == "" {
		jsonError(w, "unsupported process action", 400)
		return
	}
	cmd := AgentCommand{PID: pid}
	res, err := a.sendCommand(r.PathValue("id"), act, cmd, 15*time.Second)
	nodeName := a.nodeName(r.PathValue("id"))
	if err != nil {
		a.audit(a.remoteIP(r), act, nodeName, fmt.Sprintf("PID %d", pid), "failed: "+err.Error())
		jsonError(w, err.Error(), 503)
		return
	}
	if !res.OK {
		a.audit(a.remoteIP(r), act, nodeName, fmt.Sprintf("PID %d", pid), "failed: "+res.Error)
		jsonError(w, res.Error, 502)
		return
	}
	a.audit(a.remoteIP(r), act, nodeName, fmt.Sprintf("PID %d", pid), "success")
	if len(res.Data) > 0 {
		writeRawJSON(w, 200, res.Data)
	} else {
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}
func (a *App) nodeStopped(w http.ResponseWriter, r *http.Request) {
	a.commandJSON(w, r, "stopped_list", AgentCommand{}, 8*time.Second)
}
func (a *App) nodeStartStopped(w http.ResponseWriter, r *http.Request) {
	rid := r.PathValue("rid")
	if len(rid) < 8 || len(rid) > 80 {
		jsonError(w, "invalid restart id", 400)
		return
	}
	res, err := a.sendCommand(r.PathValue("id"), "process_start_saved", AgentCommand{RestartID: rid}, 15*time.Second)
	node := a.nodeName(r.PathValue("id"))
	if err != nil {
		a.audit(a.remoteIP(r), "process_start_saved", node, rid, "failed: "+err.Error())
		jsonError(w, err.Error(), 503)
		return
	}
	if !res.OK {
		a.audit(a.remoteIP(r), "process_start_saved", node, rid, "failed: "+res.Error)
		jsonError(w, res.Error, 502)
		return
	}
	a.audit(a.remoteIP(r), "process_start_saved", node, rid, "success")
	writeRawJSON(w, 200, res.Data)
}
func (a *App) nodeDisks(w http.ResponseWriter, r *http.Request) {
	a.commandJSON(w, r, "disk_info", AgentCommand{}, 8*time.Second)
}
func (a *App) commandJSON(w http.ResponseWriter, r *http.Request, action string, cmd AgentCommand, to time.Duration) {
	res, err := a.sendCommand(r.PathValue("id"), action, cmd, to)
	if err != nil {
		jsonError(w, err.Error(), 503)
		return
	}
	if !res.OK {
		jsonError(w, res.Error, 502)
		return
	}
	if len(res.Data) == 0 {
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	writeRawJSON(w, 200, res.Data)
}
func (a *App) nodeName(id string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if n := a.state.Nodes[id]; n != nil {
		return n.Name
	}
	return id
}

func (a *App) sendCommand(nodeID, action string, cmd AgentCommand, timeout time.Duration) (AgentResult, error) {
	a.mu.RLock()
	rt := a.runtime[nodeID]
	n := a.state.Nodes[nodeID]
	online := n != nil && nodeIsOnline(n, rt)
	a.mu.RUnlock()
	if rt == nil {
		return AgentResult{}, errors.New("node not found")
	}
	if !online {
		return AgentResult{}, errors.New("node is offline")
	}
	cmd.Protocol = protocolVersion
	cmd.ID = randomHex(12)
	cmd.Action = action
	cmd.Timestamp = time.Now().Unix()
	ch := make(chan AgentResult, 1)
	rt.pendingMu.Lock()
	rt.Pending[cmd.ID] = ch
	rt.pendingMu.Unlock()
	defer func() { rt.pendingMu.Lock(); delete(rt.Pending, cmd.ID); rt.pendingMu.Unlock() }()
	select {
	case rt.Commands <- cmd:
	default:
		return AgentResult{}, errors.New("node command queue is busy")
	}
	select {
	case res := <-ch:
		return res, nil
	case <-time.After(timeout):
		return AgentResult{}, errors.New("agent command timeout")
	}
}

func (a *App) agentRegister(w http.ResponseWriter, r *http.Request) {
	if !a.allowEnrollment(a.remoteIP(r)) {
		jsonErrorCode(w, "ENROLLMENT_RATE_LIMITED", "首次注册请求过于频繁", "请稍后重试", http.StatusTooManyRequests)
		return
	}
	var in struct {
		Token        string     `json:"token"`
		Name         string     `json:"name,omitempty"`
		EnrollmentID string     `json:"enrollment_id,omitempty"`
		AgentVersion string     `json:"agent_version,omitempty"`
		Protocol     int        `json:"protocol"`
		System       SystemInfo `json:"system"`
	}
	if !decodeJSON(w, r, &in, 1<<20) {
		return
	}
	if in.Protocol == 0 {
		jsonErrorCode(w, "MISSING_PROTOCOL_VERSION", "Agent 未提供 Protocol 版本", "请升级 NodeLume Agent", http.StatusUpgradeRequired)
		return
	}
	if in.Protocol < protocolVersion {
		jsonErrorCode(w, "AGENT_PROTOCOL_TOO_OLD", fmt.Sprintf("Agent Protocol %d 低于 Server 支持版本 %d", in.Protocol, protocolVersion), "请升级 NodeLume Agent", http.StatusUpgradeRequired)
		return
	}
	if in.Protocol > protocolVersion {
		jsonErrorCode(w, "SERVER_PROTOCOL_TOO_OLD", fmt.Sprintf("Agent Protocol %d 高于 Server 支持版本 %d", in.Protocol, protocolVersion), "请升级 NodeLume Server", http.StatusUpgradeRequired)
		return
	}
	in.Token = strings.TrimSpace(in.Token)
	if in.Token == "" {
		jsonErrorCode(w, "INVALID_ENROLLMENT_TOKEN", "Enrollment Token 不能为空", "请重新生成接入 Token", 401)
		return
	}
	now := time.Now().Unix()
	receiptKey := ""
	if strings.TrimSpace(in.EnrollmentID) != "" {
		receiptKey = hashString(in.Token + "|" + strings.TrimSpace(in.EnrollmentID))
	}
	a.mu.Lock()
	// Idempotency first: a retry after the original response was lost receives the same identity.
	if receiptKey != "" {
		if rec, ok := a.state.EnrollmentReceipts[receiptKey]; ok && rec.ExpiresAt > now {
			if n := a.state.Nodes[rec.NodeID]; n != nil {
				a.mu.Unlock()
				writeJSON(w, 200, map[string]any{"node_id": rec.NodeID, "secret": rec.Secret, "server_version": serverVersion, "protocol_min": protocolVersion, "protocol_max": protocolVersion, "report_interval_sec": n.ReportIntervalSec})
				return
			}
		}
	}
	th := hashString(in.Token)
	e, ok := a.state.Enrollments[th]
	if !ok || (e.ExpiresAt > 0 && now > e.ExpiresAt) {
		a.mu.Unlock()
		jsonErrorCode(w, "INVALID_ENROLLMENT_TOKEN", "Enrollment Token 无效或已过期", "请在 Web 中重新生成接入 Token", 401)
		return
	}
	var n *PersistNode
	if e.Reusable {
		id := randomHex(12)
		name := strings.TrimSpace(in.Name)
		if name == "" {
			name = strings.TrimSpace(e.Name)
		}
		if name == "" {
			name = "node-" + id[:6]
		}
		n = &PersistNode{ID: id, Name: name, Group: "默认分组", ReportIntervalSec: 2, CreatedAt: now}
		a.state.Nodes[id] = n
		a.runtime[id] = newRuntimeNode()
		e.Joined++
		a.state.Enrollments[th] = e
	} else {
		n = a.state.Nodes[e.NodeID]
		if n == nil {
			delete(a.state.Enrollments, th)
			a.mu.Unlock()
			jsonErrorCode(w, "NODE_NOT_FOUND", "指定节点不存在", "请重新创建接入 Token", 404)
			return
		}
	}
	secret := randomToken(32)
	if n.Registered && n.AgentSecret != "" {
		n.PreviousAgentSecret = n.AgentSecret
		n.PreviousSecretExpiresAt = time.Now().Add(5 * time.Minute).Unix()
	}
	n.SecretHash = hashString(secret)
	n.AgentSecret = secret
	if strings.TrimSpace(in.Name) != "" {
		n.Name = strings.TrimSpace(in.Name)
	}
	n.Registered = true
	n.System = in.System
	n.System.Protocol = in.Protocol
	if in.AgentVersion != "" {
		n.System.Agent = strings.TrimPrefix(strings.TrimSpace(in.AgentVersion), "v")
	}
	if n.ReportIntervalSec == 0 {
		n.ReportIntervalSec = 2
	}
	if !e.Reusable {
		delete(a.state.Enrollments, th)
	}
	if a.runtime[n.ID] == nil {
		a.runtime[n.ID] = newRuntimeNode()
	}
	if receiptKey != "" {
		a.state.EnrollmentReceipts[receiptKey] = EnrollmentReceipt{NodeID: n.ID, Secret: secret, ExpiresAt: time.Now().Add(10 * time.Minute).Unix()}
	}
	a.auditLocked(a.remoteIP(r), "agent_register", n.Name, in.System.OS+" / "+in.System.Arch, "success")
	err := a.saveLocked()
	id, interval := n.ID, n.ReportIntervalSec
	a.mu.Unlock()
	if err != nil {
		jsonErrorCode(w, "IDENTITY_SAVE_FAILED", "Server 无法保存 Agent 身份", "请检查 Server 数据目录权限和磁盘空间", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"node_id": id, "secret": secret, "server_version": serverVersion, "protocol_min": protocolVersion, "protocol_max": protocolVersion, "report_interval_sec": interval})
}
func (a *App) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	id, authFail := a.authAgentDetailed(r)
	if authFail != nil {
		jsonErrorCode(w, authFail.Code, authFail.Reason, authFail.Action, authFail.Status)
		return
	}
	a.mu.RLock()
	registeredProtocol := 0
	if n := a.state.Nodes[id]; n != nil {
		registeredProtocol = n.System.Protocol
	}
	a.mu.RUnlock()
	if registeredProtocol > 0 && registeredProtocol < protocolVersion {
		jsonErrorCode(w, "AGENT_PROTOCOL_TOO_OLD", "Agent Protocol 与 Server 不兼容", "请升级 Agent", http.StatusUpgradeRequired)
		return
	}
	if registeredProtocol > protocolVersion {
		jsonErrorCode(w, "SERVER_PROTOCOL_TOO_OLD", "Agent Protocol 高于 Server 支持版本", "请升级 Server", http.StatusUpgradeRequired)
		return
	}
	var hb Heartbeat
	if !decodeJSON(w, r, &hb, 2<<20) {
		return
	}
	now := time.Now()
	if hb.Time == 0 {
		hb.Time = now.Unix()
	}
	a.mu.Lock()
	rt := a.runtime[id]
	if rt == nil {
		rt = newRuntimeNode()
		a.runtime[id] = rt
	}
	rt.LastSeen = now
	rt.Latest = hb
	if rt.LastHistory.IsZero() || now.Sub(rt.LastHistory) >= 5*time.Second {
		p := MetricPoint{T: now.Unix(), CPU: float32(hb.CPU), Memory: float32(hb.Memory), Disk: float32(hb.Disk), Load1: float32(hb.Load1), NetIn: float32(hb.NetIn), NetOut: float32(hb.NetOut)}
		if hb.Temperature != nil {
			p.Temp = float32(*hb.Temperature)
			p.TempValid = true
		}
		rt.History.Add(p)
		rt.LastHistory = now
	}
	if n := a.state.Nodes[id]; n != nil && hb.System.Hostname != "" {
		n.System = hb.System
	}
	desired := a.desiredAgentURLLocked()
	interval := 2
	if n := a.state.Nodes[id]; n != nil && n.ReportIntervalSec > 0 {
		interval = n.ReportIntervalSec
	}
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "server_url": desired, "server_protocol": protocolVersion, "protocol_min": protocolVersion, "protocol_max": protocolVersion, "report_interval_sec": interval})
}
func (a *App) agentCommands(w http.ResponseWriter, r *http.Request) {
	id, authFail := a.authAgentDetailed(r)
	if authFail != nil {
		jsonErrorCode(w, authFail.Code, authFail.Reason, authFail.Action, authFail.Status)
		return
	}
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait < 1 || wait > 30 {
		wait = 25
	}
	a.mu.RLock()
	rt := a.runtime[id]
	a.mu.RUnlock()
	if rt == nil {
		jsonError(w, "node not found", 404)
		return
	}
	select {
	case cmd := <-rt.Commands:
		writeJSON(w, 200, cmd)
	case <-time.After(time.Duration(wait) * time.Second):
		w.WriteHeader(204)
	case <-r.Context().Done():
		return
	}
}
func (a *App) agentResults(w http.ResponseWriter, r *http.Request) {
	id, authFail := a.authAgentDetailed(r)
	if authFail != nil {
		jsonErrorCode(w, authFail.Code, authFail.Reason, authFail.Action, authFail.Status)
		return
	}
	var res AgentResult
	if !decodeJSON(w, r, &res, 4<<20) {
		return
	}
	a.mu.RLock()
	rt := a.runtime[id]
	a.mu.RUnlock()
	if rt == nil {
		jsonError(w, "node not found", 404)
		return
	}
	rt.pendingMu.Lock()
	ch := rt.Pending[res.RequestID]
	rt.pendingMu.Unlock()
	if ch != nil {
		select {
		case ch <- res:
		default:
			{
			}
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func (a *App) desiredAgentURLLocked() string {
	if a.state.Settings.Domain != "" && (a.state.Settings.HTTPSMode == "builtin" || a.state.Settings.HTTPSMode == "proxy") {
		return domainAccessURL(a.state.Settings.Domain, a.activeListen)
	}
	return a.configuredPublicURL
}

func (a *App) maintenance() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for now := range t.C {
		a.writeRuntimeStatus()
		cut := now.Add(-time.Hour).Unix()
		a.mu.Lock()
		for _, rt := range a.runtime {
			rt.History.Prune(cut)
		}
		dirty := false
		for k, e := range a.state.Enrollments {
			if e.ExpiresAt > 0 && now.Unix() > e.ExpiresAt {
				delete(a.state.Enrollments, k)
				dirty = true
			}
		}
		for k, rec := range a.state.EnrollmentReceipts {
			if now.Unix() > rec.ExpiresAt {
				delete(a.state.EnrollmentReceipts, k)
				dirty = true
			}
		}
		for _, n := range a.state.Nodes {
			if n.PreviousAgentSecret != "" && n.PreviousSecretExpiresAt > 0 && now.Unix() > n.PreviousSecretExpiresAt {
				n.PreviousAgentSecret = ""
				n.PreviousSecretExpiresAt = 0
				dirty = true
			}
		}
		for k, s := range a.sessions {
			if now.After(s.Expires) {
				delete(a.sessions, k)
			}
		}
		if dirty {
			_ = a.saveLocked()
		}
		a.mu.Unlock()
		if now.Hour()%12 == 0 && now.Minute() == 0 {
			go a.autoRenewCertificate()
		}
	}
}

func (a *App) baseURL(r *http.Request) string {
	a.mu.RLock()
	domain, mode := a.state.Settings.Domain, a.state.Settings.HTTPSMode
	a.mu.RUnlock()
	if domain != "" && (mode == "builtin" || mode == "proxy") {
		return domainAccessURL(domain, a.activeListen)
	}
	if a.configuredPublicURL != "" {
		return a.configuredPublicURL
	}
	scheme := "http"
	if a.isHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
func (a *App) agentInstallCommand(r *http.Request, token string) string {
	base, err := a.enrollmentBaseURL(r)
	if err != nil {
		return ""
	}
	a.mu.RLock()
	repo := a.state.Settings.ReleaseRepo
	a.mu.RUnlock()
	if !validRepo(repo) {
		repo = releaseRepo
	}
	raw := "https://github.com/" + repo + "/releases/download/v" + serverVersion + "/install-agent.sh"
	return fmt.Sprintf("curl -fsSL %s | sh -s -- --server %s --token %s --version v%s --repo %s", shellQuote(raw), shellQuote(base), shellQuote(token), serverVersion, shellQuote(repo))
}

func (a *App) remoteIP(r *http.Request) string {
	peer := remoteIPRaw(r)
	p := net.ParseIP(peer)
	if p == nil || !p.IsLoopback() {
		return peer
	}
	if x := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(x) != nil {
		return x
	}
	if x := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(x) != nil {
		return x
	}
	return peer
}
func (a *App) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	p := net.ParseIP(remoteIPRaw(r))
	return p != nil && p.IsLoopback() && strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}
func (a *App) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.Printf("panic: %v", v)
				http.Error(w, "internal server error", 500)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		jsonError(w, "invalid json", 400)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeRawJSON(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}
func jsonError(w http.ResponseWriter, msg string, status int) {
	writeJSON(w, status, map[string]string{"error": msg})
}
func jsonErrorCode(w http.ResponseWriter, code, reason, action string, status int) {
	writeJSON(w, status, map[string]string{"code": code, "reason": reason, "action": action})
}
func hashString(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
func passwordKey(password string, salt []byte, iterations int) []byte {
	counter := [4]byte{0, 0, 0, 1}
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(salt)
	mac.Write(counter[:])
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		mac = hmac.New(sha256.New, []byte(password))
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}
func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func validAdminPath(p string) bool {
	if len(p) < 5 || len(p) > 49 || p[0] != '/' {
		return false
	}
	for _, r := range p[1:] {
		if !(r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	for _, bad := range []string{"/api", "/assets", "/healthz", "/install"} {
		if strings.HasPrefix(p, bad) {
			return false
		}
	}
	return true
}
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
func remoteIPRaw(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return h
	}
	return r.RemoteAddr
}
func ipInCIDRs(ip string, cidrs []string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err == nil && n.Contains(p) {
			return true
		}
	}
	return false
}
func cleanStrings(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err = os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
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
func withTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}

var _ fs.FS = webFS
var _ = io.Discard

func randomHex(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (a *App) editNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name, Group, Note string
		ReportIntervalSec int `json:"report_interval_sec"`
	}
	if !decodeJSON(w, r, &in, 1<<16) {
		return
	}
	in.Name, in.Group, in.Note = strings.TrimSpace(in.Name), strings.TrimSpace(in.Group), strings.TrimSpace(in.Note)
	if in.Name == "" || len(in.Name) > 80 || len(in.Group) > 64 || len(in.Note) > 300 {
		jsonError(w, "invalid node metadata", 400)
		return
	}
	if in.ReportIntervalSec == 0 {
		in.ReportIntervalSec = 2
	}
	allowed := map[int]bool{2: true, 5: true, 10: true, 30: true, 60: true}
	if !allowed[in.ReportIntervalSec] {
		jsonError(w, "unsupported report interval", 400)
		return
	}
	a.mu.RLock()
	n := a.state.Nodes[id]
	a.mu.RUnlock()
	if n == nil {
		jsonError(w, "node not found", 404)
		return
	}
	applied := true
	a.mu.RLock()
	rt := a.runtime[id]
	online := nodeIsOnline(n, rt)
	a.mu.RUnlock()
	if n.Registered && n.ReportIntervalSec != in.ReportIntervalSec && online {
		res, err := a.sendCommand(id, "set_report_interval", AgentCommand{Interval: in.ReportIntervalSec}, 10*time.Second)
		if err != nil || !res.OK {
			if err != nil {
				jsonError(w, err.Error(), 409)
			} else {
				jsonError(w, res.Error, 409)
			}
			return
		}
	} else if n.Registered && n.ReportIntervalSec != in.ReportIntervalSec {
		applied = false
	}
	a.mu.Lock()
	n = a.state.Nodes[id]
	old := n.Name
	n.Name = in.Name
	n.Group = in.Group
	n.Note = in.Note
	n.ReportIntervalSec = in.ReportIntervalSec
	a.auditLocked(a.remoteIP(r), "edit_node", n.Name, fmt.Sprintf("%s -> %s; report %ds", old, n.Name, in.ReportIntervalSec), "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "applied": applied, "pending": !applied})
}

func (a *App) commonEnrollmentLocked() (string, Enrollment, bool) {
	for h, e := range a.state.Enrollments {
		if e.Reusable {
			return h, e, true
		}
	}
	return "", Enrollment{}, false
}
func (a *App) getCommonEnrollment(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	_, e, ok := a.commonEnrollmentLocked()
	a.mu.RUnlock()
	now := time.Now().Unix()
	active := ok && (e.ExpiresAt == 0 || e.ExpiresAt > now)
	writeJSON(w, 200, map[string]any{"active": active, "expires_at": e.ExpiresAt, "joined": e.Joined})
}
func (a *App) setCommonEnrollment(w http.ResponseWriter, r *http.Request) {
	if _, err := a.enrollmentBaseURL(r); err != nil {
		jsonError(w, err.Error(), 409)
		return
	}
	var in struct {
		Days int    `json:"days"`
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &in, 1<<16) {
		return
	}
	if in.Days != 0 && in.Days != 1 && in.Days != 7 && in.Days != 30 {
		jsonError(w, "days must be 0, 1, 7, or 30", 400)
		return
	}
	token := randomToken(32)
	exp := int64(0)
	if in.Days > 0 {
		exp = time.Now().Add(time.Duration(in.Days) * 24 * time.Hour).Unix()
	}
	a.mu.Lock()
	for h, e := range a.state.Enrollments {
		if e.Reusable {
			delete(a.state.Enrollments, h)
		}
	}
	a.state.Enrollments[hashString(token)] = Enrollment{Name: strings.TrimSpace(in.Name), ExpiresAt: exp, Reusable: true}
	a.auditLocked(a.remoteIP(r), "common_enrollment", "", "common enrollment token generated", "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"token": token, "expires_at": exp, "install_command": a.agentInstallCommand(r, token)})
}
func (a *App) revokeCommonEnrollment(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	for h, e := range a.state.Enrollments {
		if e.Reusable {
			delete(a.state.Enrollments, h)
		}
	}
	a.auditLocked(a.remoteIP(r), "common_enrollment", "", "common enrollment token revoked", "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) saveLogSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RetentionDays int `json:"retention_days"`
		MaxMiB        int `json:"max_mib"`
	}
	if !decodeJSON(w, r, &in, 1<<16) {
		return
	}
	days := map[int]bool{1: true, 3: true, 7: true, 14: true, 30: true}
	caps := map[int]bool{10: true, 25: true, 50: true, 100: true, 200: true, 500: true}
	if !days[in.RetentionDays] || !caps[in.MaxMiB] {
		jsonError(w, "unsupported log settings", 400)
		return
	}
	a.mu.Lock()
	a.state.Settings.LogRetentionDays = in.RetentionDays
	a.state.Settings.LogMaxMiB = in.MaxMiB
	a.auditLocked(a.remoteIP(r), "log_settings", "", fmt.Sprintf("%d days / %d MiB", in.RetentionDays, in.MaxMiB), "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if a.logWriter != nil {
		a.logWriter.Configure(in.RetentionDays, in.MaxMiB)
	}
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (a *App) runtimeLogs(w http.ResponseWriter, r *http.Request) {
	if a.logWriter == nil {
		writeJSON(w, 200, map[string]any{"text": "", "bytes": 0})
		return
	}
	text, n, err := a.logWriter.Tail(256 << 10)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]any{"text": text, "bytes": n})
}
func (a *App) runtimeLogStream(w http.ResponseWriter, r *http.Request) {
	if a.logWriter == nil {
		jsonError(w, "runtime log unavailable", 503)
		return
	}
	f, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "streaming unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	ch, cancel := a.logWriter.Subscribe()
	defer cancel()
	_, _ = io.WriteString(w, "event: ready\ndata: ok\n\n")
	f.Flush()
	for {
		select {
		case line, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(line)
			_, _ = fmt.Fprintf(w, "event: log\ndata: %s\n\n", b)
			f.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
func (a *App) clearRuntimeLogs(w http.ResponseWriter, r *http.Request) {
	if a.logWriter != nil {
		if err := a.logWriter.Clear(); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
	}
	a.audit(a.remoteIP(r), "clear_runtime_logs", "", "server runtime logs cleared", "success")
	writeJSON(w, 200, map[string]any{"ok": true})
}
