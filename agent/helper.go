package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type storedRecord struct {
	StoppedRecord
	Exe  string   `json:"exe,omitempty"`
	Args []string `json:"args,omitempty"`
	Cwd  string   `json:"cwd,omitempty"`
	UID  uint32   `json:"uid,omitempty"`
	GID  uint32   `json:"gid,omitempty"`
}

type serviceState struct {
	Unit    string `json:"unit"`
	Active  string `json:"active"`
	Sub     string `json:"sub"`
	MainPID int    `json:"main_pid"`
}

var unitRE = regexp.MustCompile(`^[A-Za-z0-9_.@-]+\.service$`)

func helperSocketPath() string {
	if v := os.Getenv("NODELUME_HELPER_SOCKET"); v != "" {
		return v
	}
	return helperSocket
}

func runHelper(socketOverride string) error {
	var ln net.Listener
	var err error
	if socketOverride != "" {
		_ = os.Remove(socketOverride)
		if err = os.MkdirAll(filepath.Dir(socketOverride), 0755); err != nil {
			return err
		}
		ln, err = net.Listen("unix", socketOverride)
		if err != nil {
			return err
		}
		_ = os.Chmod(socketOverride, 0660)
		defer os.Remove(socketOverride)
	} else if os.Getenv("LISTEN_FDS") != "" {
		f := os.NewFile(uintptr(3), "nodelume-helper.socket")
		if f == nil {
			return errors.New("systemd socket fd unavailable")
		}
		ln, err = net.FileListener(f)
		_ = f.Close()
		if err != nil {
			return err
		}
	} else {
		return errors.New("helper requires systemd socket activation")
	}
	defer ln.Close()

	for {
		if ul, ok := ln.(*net.UnixListener); ok {
			_ = ul.SetDeadline(time.Now().Add(55 * time.Second))
		}
		c, er := ln.Accept()
		if ne, ok := er.(net.Error); ok && ne.Timeout() {
			return nil
		}
		if er != nil {
			return er
		}
		if !authorizedPeer(c) {
			_ = c.Close()
			continue
		}
		_ = c.SetDeadline(time.Now().Add(45 * time.Second))
		handleHelperConn(c)
		_ = c.Close()
	}
}

func authorizedPeer(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var serr error
	if err = raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || serr != nil || cred == nil {
		return false
	}
	if cred.Uid == 0 {
		return true
	} // local administrative tests / CLI only
	u, err := user.Lookup("nodelume-agent")
	if err != nil {
		return false
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(uid) == cred.Uid
}

func handleHelperConn(c net.Conn) {
	var req HelperRequest
	dec := json.NewDecoder(io.LimitReader(c, 64<<10))
	if err := dec.Decode(&req); err != nil {
		writeHelper(c, nil, err)
		return
	}
	var out any
	var err error
	switch req.Action {
	case "process_info":
		out, err = readProcessDetail(req.PID)
	case "process_terminate":
		out, err = stopProcess(req.PID, syscall.SIGTERM)
	case "process_kill":
		out, err = stopProcess(req.PID, syscall.SIGKILL)
	case "process_restart":
		out, err = restartProcess(req.PID)
	case "stopped_list":
		out, err = publicStopped()
	case "process_start_saved":
		out, err = startSaved(req.RestartID)
	case "service_stop", "service_restart":
		if req.PID <= 0 {
			err = errors.New("pid required")
		} else {
			d, er := readProcessDetail(req.PID)
			if er != nil {
				err = er
			} else if d.Service == "" {
				err = errors.New("process is not associated with a systemd service")
			} else if req.Action == "service_stop" {
				if !safeService(d.Service) {
					err = errors.New("service is protected or invalid")
				} else {
					rec := storedRecord{StoppedRecord: StoppedRecord{
						ID: fmt.Sprintf("%d-%d", time.Now().UnixNano(), req.PID), Name: d.Name,
						Launch: d.Launch, Service: d.Service, StoppedAt: time.Now().Unix(), CanStart: true,
						Note: "systemd service stopped by NodeLume",
					}}
					// Persist the recovery record before stopping the service. If we cannot
					// persist a safe recovery path, do not perform the destructive action.
					if er := saveStopped(rec); er != nil {
						err = fmt.Errorf("cannot save service recovery record: %w", er)
					} else {
						out, err = serviceAction(d.Service, "stop")
						if err != nil {
							_ = removeStopped(rec.ID)
						}
					}
				}
			} else {
				out, err = serviceAction(d.Service, "restart")
			}
		}
	case "agent_upgrade":
		if !validVersion(req.Version) || !validRepo(req.Repo) {
			err = errors.New("invalid update target")
		} else {
			err = performAgentUpgrade(strings.TrimPrefix(req.Version, "v"), req.Repo, "/etc/nodelume/release.pub", true)
			if err == nil {
				out = map[string]any{"status": "installed_pending_restart", "version": strings.TrimPrefix(req.Version, "v")}
			}
		}
	case "agent_update_commit":
		err = commitAgentUpdate()
		out = map[string]any{"status": "committed"}
	default:
		err = errors.New("unsupported privileged action")
	}
	writeHelper(c, out, err)
}

func writeHelper(w io.Writer, out any, err error) {
	resp := HelperResponse{OK: err == nil}
	if err != nil {
		resp.Error = err.Error()
	} else if out != nil {
		resp.Data, _ = json.Marshal(out)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func readProcessDetail(pid int) (ProcessDetail, error) {
	if pid <= 0 {
		return ProcessDetail{}, errors.New("invalid pid")
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ProcessDetail{}, err
	}
	fields := parseStatus(stat)
	name := fields["Name"]
	uid64, _ := strconv.ParseUint(strings.Fields(fields["Uid"])[0], 10, 32)
	userName := strconv.FormatUint(uid64, 10)
	if u, er := user.LookupId(userName); er == nil {
		userName = u.Username
	}
	state := fields["State"]
	if f := strings.Fields(state); len(f) > 0 {
		state = f[0]
	}
	ppid, _ := strconv.Atoi(fields["PPid"])
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	args := readCmdline(pid)
	command := sanitizeArgs(args)
	if command == "" {
		command = "[" + name + "]"
	}
	service, cgroupContainer := readCgroupClass(pid)
	parentName := procName(ppid)
	launch := "未知"
	note := ""
	if pid == 1 {
		launch = "init"
	} else if strings.HasPrefix(name, "[") || (exe == "" && len(args) == 0) {
		launch = "内核线程"
	} else if cgroupContainer {
		launch = "容器"
		note = "容器进程由运行时管理，不允许由 NodeLume 直接重启"
	} else if service != "" {
		if ppid == 1 {
			launch = "systemd 服务"
		} else {
			launch = "子进程 / systemd"
		}
	} else if ancestorHas(pid, []string{"cron", "crond", "CRON"}) {
		launch = "Cron 任务"
		note = "Cron 任务不由 NodeLume 直接重新启动"
	} else if ancestorHas(pid, []string{"bash", "sh", "zsh", "dash", "fish", "sshd"}) {
		launch = "手动 / 独立二进制"
	} else if ppid == 1 {
		launch = "独立后台进程"
	} else {
		launch = "普通进程"
	}
	protected := isProtectedProcess(pid, name, exe, service)
	canTerminate := !protected && pid > 1
	canKill := canTerminate
	restartMode := ""
	canRestart := false
	if !protected && service != "" && safeService(service) {
		canRestart = true
		restartMode = "systemd"
	}
	if !protected && service == "" && !cgroupContainer && !strings.Contains(launch, "Cron") && exe != "" && len(args) > 0 {
		if hasSensitiveRestartArgs(args) {
			note = "检测到敏感启动参数；为避免把密钥持久化到恢复记录，NodeLume 禁用此进程的直接重启/恢复"
		} else {
			canRestart = true
			restartMode = "direct"
		}
	}
	parent := "—"
	if ppid > 0 {
		parent = fmt.Sprintf("%s (%d)", parentName, ppid)
	}
	memMB := readRSSMB(pid)
	return ProcessDetail{ProcessSummary: ProcessSummary{PID: pid, Name: name, MemoryMB: memMB, User: userName, State: state}, Command: command, Launch: launch, Service: service, Parent: parent, Exe: exe, Cwd: cwd, Tree: processTree(pid), Protected: protected, CanTerminate: canTerminate, CanKill: canKill, CanRestart: canRestart, RestartMode: restartMode, Note: note}, nil
}

func parseStatus(b []byte) map[string]string {
	m := map[string]string{}
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := s.Text()
		if i := strings.IndexByte(line, ':'); i > 0 {
			m[line[:i]] = strings.TrimSpace(line[i+1:])
		}
	}
	return m
}
func procName(pid int) string {
	if pid <= 0 {
		return ""
	}
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return strings.TrimSpace(string(b))
}
func readCmdline(pid int) []string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(b) == 0 {
		return nil
	}
	parts := bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			out = append(out, string(p))
		}
	}
	return out
}
func sensitiveArg(s string) bool {
	x := strings.ToLower(strings.TrimLeft(s, "-"))
	for _, k := range []string{"password", "passwd", "token", "secret", "api-key", "apikey", "authorization", "auth", "private-key", "access-key"} {
		if strings.Contains(x, k) {
			return true
		}
	}
	return false
}
func hasSensitiveRestartArgs(args []string) bool {
	for _, a := range args {
		if i := strings.IndexByte(a, '='); i > 0 && sensitiveArg(a[:i]) {
			return true
		}
		if sensitiveInlineValue(a) {
			return true
		}
		if strings.HasPrefix(a, "-") && sensitiveArg(a) {
			return true
		}
		if strings.Contains(a, "://") && strings.Contains(a, "@") {
			if u, err := url.Parse(a); err == nil && u.User != nil {
				return true
			}
		}
	}
	return false
}

func sanitizeArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	out := make([]string, 0, len(args))
	redactNext := false
	for _, a := range args {
		if redactNext {
			out = append(out, "******")
			redactNext = false
			continue
		}
		if i := strings.IndexByte(a, '='); i > 0 && sensitiveArg(a[:i]) {
			out = append(out, a[:i]+"=******")
			continue
		}
		if sensitiveInlineValue(a) {
			out = append(out, "******")
			continue
		}
		a = redactURLUserInfo(a)
		out = append(out, a)
		if strings.HasPrefix(a, "-") && sensitiveArg(a) {
			redactNext = true
		}
	}
	return strings.Join(out, " ")
}

func sensitiveInlineValue(s string) bool {
	x := strings.ToLower(s)
	for _, k := range []string{"authorization:", "proxy-authorization:", "bearer ", "password=", "passwd=", "token=", "secret=", "api_key=", "apikey=", "api-key=", "access_key=", "private_key="} {
		if strings.Contains(x, k) {
			return true
		}
	}
	return false
}

func redactURLUserInfo(s string) string {
	if !strings.Contains(s, "://") || !strings.Contains(s, "@") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = url.User("******")
	return u.String()
}
func readCgroupClass(pid int) (string, bool) {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	s := string(b)
	container := strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "libpod") || strings.Contains(s, "containerd")
	for _, line := range strings.Split(s, "\n") {
		for _, seg := range strings.Split(line, "/") {
			if unitRE.MatchString(seg) {
				return seg, container
			}
		}
	}
	return "", container
}
func ancestorHas(pid int, names []string) bool {
	seen := map[int]bool{}
	for i := 0; i < 10 && pid > 1; i++ {
		if seen[pid] {
			break
		}
		seen[pid] = true
		b, er := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if er != nil {
			break
		}
		f := parseStatus(b)
		n := f["Name"]
		for _, x := range names {
			if n == x {
				return true
			}
		}
		pid, _ = strconv.Atoi(f["PPid"])
	}
	return false
}
func processTree(pid int) string {
	type node struct {
		pid  int
		name string
	}
	chain := []node{}
	seen := map[int]bool{}
	p := pid
	for i := 0; i < 8 && p > 0; i++ {
		if seen[p] {
			break
		}
		seen[p] = true
		n := procName(p)
		if n == "" {
			n = "?"
		}
		chain = append(chain, node{p, n})
		if p == 1 {
			break
		}
		b, er := os.ReadFile(fmt.Sprintf("/proc/%d/status", p))
		if er != nil {
			break
		}
		p, _ = strconv.Atoi(parseStatus(b)["PPid"])
	}
	var sb strings.Builder
	for i := len(chain) - 1; i >= 0; i-- {
		depth := len(chain) - 1 - i
		if depth > 0 {
			sb.WriteString(strings.Repeat("   ", depth-1))
			sb.WriteString("└─ ")
		}
		fmt.Fprintf(&sb, "%s (%d)", chain[i].name, chain[i].pid)
		if i > 0 {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}
func readRSSMB(pid int) float64 {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	v := parseStatus(b)["VmRSS"]
	f := strings.Fields(v)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseFloat(f[0], 64)
	return n / 1024
}

func isProtectedProcess(pid int, name, exe, unit string) bool {
	if pid <= 1 {
		return true
	}
	n := strings.ToLower(name)
	e := strings.ToLower(exe)
	if strings.Contains(n, "nodelume") || strings.Contains(e, "nodelume-agent") {
		return true
	}
	for _, x := range []string{"systemd", "init", "sshd", "systemd-journald", "systemd-logind", "systemd-networkd", "systemd-resolved", "systemd-udevd", "dbus-daemon", "networkmanager", "firewalld", "containerd", "dockerd", "cron", "crond", "auditd", "polkitd"} {
		if n == x {
			return true
		}
	}
	if unit != "" && !safeService(unit) {
		return true
	}
	return false
}
func safeService(unit string) bool {
	if !unitRE.MatchString(unit) {
		return false
	}
	u := strings.ToLower(unit)
	for _, p := range []string{"nodelume-", "ssh.service", "sshd.service", "systemd-", "networkmanager.service", "networking.service", "firewalld.service", "ufw.service", "dbus.service", "polkit.service", "docker.service", "containerd.service", "cron.service", "crond.service", "auditd.service"} {
		if strings.HasPrefix(u, p) || u == p {
			return false
		}
	}
	return true
}
func systemctlPath() string {
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if st, er := os.Stat(p); er == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
func systemdServiceInfo(unit string) (serviceState, error) {
	if !safeService(unit) {
		return serviceState{}, errors.New("service is protected or invalid")
	}
	p := systemctlPath()
	if p == "" {
		return serviceState{}, errors.New("systemd not available")
	}
	cmd := exec.Command(p, "show", "--no-pager", "--property=Id,ActiveState,SubState,MainPID", unit)
	b, err := cmd.Output()
	if err != nil {
		return serviceState{}, fmt.Errorf("systemctl show failed")
	}
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(l, '='); i > 0 {
			m[l[:i]] = l[i+1:]
		}
	}
	pid, _ := strconv.Atoi(m["MainPID"])
	return serviceState{Unit: m["Id"], Active: m["ActiveState"], Sub: m["SubState"], MainPID: pid}, nil
}
func serviceAction(unit, action string) (any, error) {
	if !safeService(unit) {
		return nil, errors.New("service is protected or invalid")
	}
	if action != "start" && action != "stop" && action != "restart" {
		return nil, errors.New("unsupported service action")
	}
	p := systemctlPath()
	if p == "" {
		return nil, errors.New("systemd not available")
	}
	cmd := exec.Command(p, action, unit)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemd %s failed", action)
	}
	st, _ := systemdServiceInfo(unit)
	return st, nil
}

func stopProcess(pid int, sig syscall.Signal) (any, error) {
	d, err := readProcessDetail(pid)
	if err != nil {
		return nil, err
	}
	if d.Protected || !d.CanTerminate {
		return nil, errors.New("process is protected")
	}
	if sig != syscall.SIGTERM && sig != syscall.SIGKILL {
		return nil, errors.New("unsupported process signal")
	}
	rec, can := captureRestart(pid, d)
	if can {
		// A recoverable stop is allowed only after the root-only local recovery
		// snapshot is safely persisted. This prevents "stopped but unrecoverable"
		// states when the helper cannot write its recovery store.
		if err = saveStopped(rec); err != nil {
			return nil, fmt.Errorf("cannot save process recovery record: %w", err)
		}
	}
	if err = syscall.Kill(pid, sig); err != nil {
		if can {
			_ = removeStopped(rec.ID)
		}
		return nil, err
	}
	wait := 5 * time.Second
	if sig == syscall.SIGKILL {
		wait = 2 * time.Second
	}
	if !waitGone(pid, wait) {
		if can {
			_ = removeStopped(rec.ID)
		}
		if sig == syscall.SIGTERM {
			return nil, errors.New("process did not exit after SIGTERM")
		}
		return nil, errors.New("process did not exit after SIGKILL")
	}
	return map[string]any{"pid": pid, "signal": sig.String(), "stopped": publicRecord(rec, can), "exited": true}, nil
}
func restartProcess(pid int) (any, error) {
	d, err := readProcessDetail(pid)
	if err != nil {
		return nil, err
	}
	if d.Protected || !d.CanRestart {
		return nil, errors.New("process cannot be safely restarted")
	}
	if d.RestartMode == "systemd" {
		return serviceAction(d.Service, "restart")
	}
	rec, can := captureRestart(pid, d)
	if !can {
		return nil, errors.New("restart snapshot unavailable")
	}
	// Persist recovery before stopping the old process. If starting the new
	// process fails, the user can still start it from the "stopped" list.
	if err = saveStopped(rec); err != nil {
		return nil, fmt.Errorf("cannot save process recovery record: %w", err)
	}
	if err = syscall.Kill(pid, syscall.SIGTERM); err != nil {
		_ = removeStopped(rec.ID)
		return nil, err
	}
	if !waitGone(pid, 5*time.Second) {
		_ = removeStopped(rec.ID)
		return nil, errors.New("process did not exit after SIGTERM; restart aborted")
	}
	npid, err := startRecord(rec)
	if err != nil {
		// Keep the saved record so the user can retry the safe start manually.
		return nil, fmt.Errorf("process stopped but restart failed; recovery record retained: %w", err)
	}
	_ = removeStopped(rec.ID)
	return map[string]any{"old_pid": pid, "new_pid": npid, "mode": "direct"}, nil
}
func waitGone(pid int, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if processExited(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return processExited(pid)
}

func processExited(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return true
	}
	// A zombie has exited and can no longer execute code; its PID remains only
	// until the parent reaps it. Treat it as exited for stop/restart semantics.
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	i := bytes.LastIndexByte(b, ')')
	return i >= 0 && i+2 < len(b) && b[i+2] == 'Z'
}
func captureRestart(pid int, d ProcessDetail) (storedRecord, bool) {
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), pid)
	r := storedRecord{StoppedRecord: StoppedRecord{ID: id, Name: d.Name, Launch: d.Launch, Service: d.Service, StoppedAt: time.Now().Unix(), CanStart: d.CanRestart, Note: d.Note}}
	if d.RestartMode == "systemd" {
		return r, true
	}
	args := readCmdline(pid)
	if hasSensitiveRestartArgs(args) {
		r.CanStart = false
		r.Note = "sensitive command arguments detected; direct recovery intentionally disabled"
		return r, false
	}
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	b, er := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if er != nil || exe == "" || len(args) == 0 {
		return r, false
	}
	f := parseStatus(b)
	uids := strings.Fields(f["Uid"])
	gids := strings.Fields(f["Gid"])
	if len(uids) == 0 || len(gids) == 0 {
		return r, false
	}
	uv, _ := strconv.ParseUint(uids[0], 10, 32)
	gv, _ := strconv.ParseUint(gids[0], 10, 32)
	r.Exe = exe
	r.Args = args
	r.Cwd = cwd
	r.UID = uint32(uv)
	r.GID = uint32(gv)
	return r, true
}
func publicRecord(r storedRecord, ok bool) any {
	if !ok {
		return nil
	}
	return r.StoppedRecord
}
func loadStopped() ([]storedRecord, error) {
	b, err := os.ReadFile(stoppedPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var x []storedRecord
	if err = json.Unmarshal(b, &x); err != nil {
		return nil, err
	}
	return x, nil
}
func saveStopped(r storedRecord) error {
	x, _ := loadStopped()
	x = append([]storedRecord{r}, x...)
	if len(x) > 100 {
		x = x[:100]
	}
	if err := os.MkdirAll(filepath.Dir(stoppedPath), 0700); err != nil {
		return err
	}
	b, _ := json.Marshal(x)
	tmp := stoppedPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, stoppedPath)
}
func removeStopped(id string) error {
	x, err := loadStopped()
	if err != nil {
		return err
	}
	out := x[:0]
	for _, r := range x {
		if r.ID != id {
			out = append(out, r)
		}
	}
	return writeStopped(out)
}

func publicStopped() ([]StoppedRecord, error) {
	x, err := loadStopped()
	if err != nil {
		return nil, err
	}
	out := make([]StoppedRecord, 0, len(x))
	for _, r := range x {
		out = append(out, r.StoppedRecord)
	}
	return out, nil
}
func startSaved(id string) (any, error) {
	if id == "" || len(id) > 128 {
		return nil, errors.New("invalid restart id")
	}
	x, err := loadStopped()
	if err != nil {
		return nil, err
	}
	for i, r := range x {
		if r.ID != id {
			continue
		}
		if !r.CanStart {
			return nil, errors.New("record is not restartable")
		}
		var out any
		if r.Service != "" {
			out, err = serviceAction(r.Service, "start")
		} else {
			var pid int
			pid, err = startRecord(r)
			out = map[string]any{"pid": pid, "mode": "direct"}
		}
		if err != nil {
			return nil, err
		}
		x = append(x[:i], x[i+1:]...)
		_ = writeStopped(x)
		return out, nil
	}
	return nil, errors.New("restart record not found")
}
func writeStopped(x []storedRecord) error {
	if err := os.MkdirAll(filepath.Dir(stoppedPath), 0700); err != nil {
		return err
	}
	b, _ := json.Marshal(x)
	tmp := stoppedPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, stoppedPath)
}
func startRecord(r storedRecord) (int, error) {
	if r.Exe == "" || len(r.Args) == 0 {
		return 0, errors.New("missing direct-start snapshot")
	}
	if st, err := os.Stat(r.Exe); err != nil || st.IsDir() {
		return 0, errors.New("saved executable is unavailable")
	}
	devnull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer devnull.Close()
	attr := &os.ProcAttr{Dir: r.Cwd, Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, Files: []*os.File{devnull, devnull, devnull}, Sys: &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: r.UID, Gid: r.GID}}}
	p, err := os.StartProcess(r.Exe, r.Args, attr)
	if err != nil {
		return 0, err
	}
	pid := p.Pid
	_ = p.Release()
	return pid, nil
}
