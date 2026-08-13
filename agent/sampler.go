package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func newSampler() *Sampler {
	s := &Sampler{sys: readSystemInfo(), procTicks: map[int]procCPU{}}
	s.lastCPU = readCPUTimes()
	s.lastNetIn, s.lastNetOut = readNetworkTotals()
	s.lastNetAt = time.Now()
	s.lastProcTotal = s.lastCPU.total
	s.scanProcessesLocked(s.lastProcTotal)
	return s
}
func (s *Sampler) Sample() Heartbeat {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	curCPU := readCPUTimes()
	cpu := cpuPercent(s.lastCPU, curCPU)
	s.lastCPU = curCPU
	total, avail := readMemory()
	used := uint64(0)
	if total > avail {
		used = total - avail
	}
	du, dt := rootDisk()
	l1, l5, l15 := readLoad()
	ni, no := readNetworkTotals()
	secs := now.Sub(s.lastNetAt).Seconds()
	inRate, outRate := 0.0, 0.0
	if secs > 0 {
		if ni >= s.lastNetIn {
			inRate = float64(ni-s.lastNetIn) / secs
		}
		if no >= s.lastNetOut {
			outRate = float64(no-s.lastNetOut) / secs
		}
	}
	s.lastNetIn, s.lastNetOut, s.lastNetAt = ni, no, now
	if now.Sub(s.lastProcScan) >= 5*time.Second {
		s.scanProcessesLocked(curCPU.total)
	}
	return Heartbeat{Time: now.Unix(), CPU: cpu, Memory: pct(used, total), MemoryUsed: used, MemoryAvail: avail, Disk: pct(du, dt), DiskUsed: du, DiskTotal: dt, Temperature: readTemperature(), Load1: l1, Load5: l5, Load15: l15, NetIn: inRate, NetOut: outRate, Uptime: readUptime(), Processes: countProcesses(), TopCPU: append([]ProcessSummary(nil), s.topCPU...), TopMemory: append([]ProcessSummary(nil), s.topMem...), System: s.sys}
}
func (s *Sampler) scanProcesses() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanProcessesLocked(readCPUTimes().total)
}
func (s *Sampler) scanProcessesLocked(total uint64) {
	entries, _ := os.ReadDir("/proc")
	totalMem := s.sys.MemoryTotal
	dt := total - s.lastProcTotal
	cores := float64(runtime.NumCPU())
	if cores < 1 {
		cores = 1
	}
	all := make([]ProcessSummary, 0, 128)
	next := map[int]procCPU{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		ticks, err := readProcTicks(pid)
		if err != nil {
			continue
		}
		next[pid] = procCPU{ticks: ticks}
		cpu := 0.0
		if old, ok := s.procTicks[pid]; ok && dt > 0 && ticks >= old.ticks {
			cpu = float64(ticks-old.ticks) / float64(dt) * 100 * cores
			if cpu > 100*cores {
				cpu = 100 * cores
			}
		}
		p, err := readProcessSummary(pid, totalMem, cpu)
		if err == nil {
			all = append(all, p)
		}
	}
	s.procTicks = next
	s.lastProcTotal = total
	s.lastProcScan = time.Now()
	sort.Slice(all, func(i, j int) bool { return all[i].CPU > all[j].CPU })
	s.topCPU = append([]ProcessSummary(nil), all[:min(len(all), 10)]...)
	sort.Slice(all, func(i, j int) bool { return all[i].MemoryMB > all[j].MemoryMB })
	s.topMem = append([]ProcessSummary(nil), all[:min(len(all), 10)]...)
}
func (s *Sampler) processList(refresh bool) ([]ProcessSummary, error) {
	if refresh {
		s.scanProcesses()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, _ := os.ReadDir("/proc")
	out := make([]ProcessSummary, 0, 256)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := readProcessSummary(pid, s.sys.MemoryTotal, s.currentProcCPULocked(pid))
		if err == nil {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CPU > out[j].CPU })
	return out, nil
}
func (s *Sampler) currentProcCPU(pid int) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentProcCPULocked(pid)
}
func (s *Sampler) currentProcCPULocked(pid int) float64 {
	for _, p := range s.topCPU {
		if p.PID == pid {
			return p.CPU
		}
	}
	for _, p := range s.topMem {
		if p.PID == pid {
			return p.CPU
		}
	}
	return 0
}

func readSystemInfo() SystemInfo {
	host, _ := os.Hostname()
	osName, osID := readOSRelease()
	var u syscall.Utsname
	_ = syscall.Uname(&u)
	mem, _ := readMemory()
	return SystemInfo{Hostname: host, OS: osName, OSID: osID, Arch: runtime.GOARCH, Kernel: charsToString(u.Release[:]), CPUModel: readCPUModel(), CPUCores: runtime.NumCPU(), MemoryTotal: mem, Agent: agentVersion, Protocol: protocolVersion}
}
func readOSRelease() (string, string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux", "linux"
	}
	defer f.Close()
	vals := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '='); i > 0 {
			vals[line[:i]] = strings.Trim(strings.TrimSpace(line[i+1:]), "\"")
		}
	}
	name := vals["PRETTY_NAME"]
	if name == "" {
		name = vals["NAME"]
	}
	if name == "" {
		name = "Linux"
	}
	id := vals["ID"]
	if id == "" {
		id = "linux"
	}
	return name, id
}
func readCPUModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Hardware") || strings.HasPrefix(line, "Processor") {
			if i := strings.IndexByte(line, ':'); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}
func readCPUTimes() cpuTimes {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	f := strings.Fields(line)
	var vals []uint64
	for _, x := range f[1:] {
		v, _ := strconv.ParseUint(x, 10, 64)
		vals = append(vals, v)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	idle := uint64(0)
	if len(vals) > 3 {
		idle += vals[3]
	}
	if len(vals) > 4 {
		idle += vals[4]
	}
	return cpuTimes{total: total, idle: idle}
}
func cpuPercent(a, b cpuTimes) float64 {
	dt := b.total - a.total
	if dt == 0 {
		return 0
	}
	di := b.idle - a.idle
	if di > dt {
		di = dt
	}
	return clamp(float64(dt-di) / float64(dt) * 100)
}
func readMemory() (uint64, uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var total, avail uint64
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		v *= 1024
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			total = v
		case "MemAvailable":
			avail = v
		}
	}
	return total, avail
}
func rootDisk() (uint64, uint64) {
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) != nil {
		return 0, 0
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	if total < free {
		return 0, total
	}
	return total - free, total
}
func readLoad() (float64, float64, float64) {
	b, _ := os.ReadFile("/proc/loadavg")
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return 0, 0, 0
	}
	a, _ := strconv.ParseFloat(f[0], 64)
	c, _ := strconv.ParseFloat(f[1], 64)
	d, _ := strconv.ParseFloat(f[2], 64)
	return a, c, d
}
func readUptime() float64 {
	b, _ := os.ReadFile("/proc/uptime")
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}
func countProcesses() int {
	es, _ := os.ReadDir("/proc")
	n := 0
	for _, e := range es {
		if e.IsDir() {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				n++
			}
		}
	}
	return n
}
func readNetworkTotals() (uint64, uint64) {
	b, _ := os.ReadFile("/proc/net/dev")
	var in, out uint64
	for _, l := range strings.Split(string(b), "\n") {
		i := strings.IndexByte(l, ':')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(l[:i])
		if name == "lo" {
			continue
		}
		f := strings.Fields(l[i+1:])
		if len(f) >= 9 {
			a, _ := strconv.ParseUint(f[0], 10, 64)
			z, _ := strconv.ParseUint(f[8], 10, 64)
			in += a
			out += z
		}
	}
	return in, out
}
func readTemperature() *float64 {
	patterns := []string{"/sys/class/thermal/thermal_zone*/temp", "/sys/class/hwmon/hwmon*/temp*_input"}
	var vals []float64
	for _, p := range patterns {
		files, _ := filepath.Glob(p)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
			if err != nil {
				continue
			}
			if v > 1000 {
				v /= 1000
			}
			if v > 0 && v < 150 {
				vals = append(vals, v)
			}
		}
	}
	if len(vals) == 0 {
		return nil
	}
	sort.Float64s(vals)
	v := vals[len(vals)-1]
	return &v
}
func readProcTicks(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0, errors.New("bad stat")
	}
	f := strings.Fields(s[i+2:])
	if len(f) < 13 {
		return 0, errors.New("short stat")
	}
	u, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	return u + st, nil
}
func readProcessSummary(pid int, totalMem uint64, cpu float64) (ProcessSummary, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ProcessSummary{}, err
	}
	p := ProcessSummary{PID: pid, CPU: cpu}
	var uid string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch strings.TrimSuffix(f[0], ":") {
		case "Name":
			p.Name = f[1]
		case "State":
			p.State = f[1]
		case "Uid":
			uid = f[1]
		case "VmRSS":
			v, _ := strconv.ParseFloat(f[1], 64)
			p.MemoryMB = v / 1024
		}
	}
	if totalMem > 0 {
		p.MemoryPct = p.MemoryMB * 1024 * 1024 / float64(totalMem) * 100
	}
	p.User = uidToName(uid)
	if sb, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		ss := string(sb)
		i := strings.LastIndex(ss, ")")
		if i >= 0 {
			f := strings.Fields(ss[i+2:])
			if len(f) > 19 {
				start, _ := strconv.ParseUint(f[19], 10, 64)
				up := readUptime()
				secs := int64(up) - int64(start/100)
				if secs > 0 {
					p.UptimeSecs = secs
				}
			}
		}
	}
	return p, nil
}

var passwdOnce sync.Once
var passwd map[string]string

func uidToName(uid string) string {
	passwdOnce.Do(func() {
		passwd = map[string]string{}
		b, _ := os.ReadFile("/etc/passwd")
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) > 2 {
				passwd[f[2]] = f[0]
			}
		}
	})
	if n := passwd[uid]; n != "" {
		return n
	}
	return uid
}
func readDisks() []DiskInfo {
	b, _ := os.ReadFile("/proc/mounts")
	seen := map[string]bool{}
	var out []DiskInfo
	skip := map[string]bool{"proc": true, "sysfs": true, "tmpfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true, "squashfs": true, "securityfs": true, "pstore": true, "debugfs": true, "tracefs": true, "configfs": true}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		dev, mnt, fs := f[0], f[1], f[2]
		if skip[fs] || seen[mnt] {
			continue
		}
		seen[mnt] = true
		var st syscall.Statfs_t
		if syscall.Statfs(mnt, &st) != nil {
			continue
		}
		tot := st.Blocks * uint64(st.Bsize)
		free := st.Bavail * uint64(st.Bsize)
		if tot == 0 {
			continue
		}
		used := tot - free
		out = append(out, DiskInfo{Name: dev, Mount: mnt, FSType: fs, Used: used, Total: tot, Percent: pct(used, tot)})
	}
	return out
}
func readNetworkInterfaces() []map[string]any {
	ifs, _ := net.Interfaces()
	out := []map[string]any{}
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		a := []string{}
		for _, x := range addrs {
			a = append(a, x.String())
		}
		out = append(out, map[string]any{"name": i.Name, "mtu": i.MTU, "flags": i.Flags.String(), "addresses": a})
	}
	return out
}
func readListeningPorts() []PortInfo {
	out := []PortInfo{}
	for _, x := range []struct{ path, proto string }{{"/proc/net/tcp", "tcp4"}, {"/proc/net/tcp6", "tcp6"}, {"/proc/net/udp", "udp4"}, {"/proc/net/udp6", "udp6"}} {
		b, err := os.ReadFile(x.path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(b), "\n")
		for _, l := range lines[1:] {
			f := strings.Fields(l)
			if len(f) < 4 {
				continue
			}
			if strings.HasPrefix(x.proto, "tcp") && f[3] != "0A" {
				continue
			}
			parts := strings.Split(f[1], ":")
			if len(parts) != 2 {
				continue
			}
			port64, _ := strconv.ParseUint(parts[1], 16, 16)
			out = append(out, PortInfo{Protocol: x.proto, Address: parts[0], Port: int(port64)})
		}
	}
	return out
}
func pct(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return clamp(float64(a) / float64(b) * 100)
}
func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
func charsToString(c []int8) string {
	b := make([]byte, 0, len(c))
	for _, x := range c {
		if x == 0 {
			break
		}
		b = append(b, byte(x))
	}
	return string(b)
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func decodeHexIPv4(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return s
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}
