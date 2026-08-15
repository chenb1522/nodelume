package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSanitizeArgs(t *testing.T) {
	got := sanitizeArgs([]string{"app", "--token", "secret-value", "--port=8080", "--password=hunter2", "-H", "Authorization: Bearer abc123", "https://user:pass@example.com/api"})
	want := "app --token ****** --port=8080 --password=****** -H ****** https://%2A%2A%2A%2A%2A%2A@example.com/api"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSensitiveRestartArgs(t *testing.T) {
	for _, args := range [][]string{
		{"app", "--token", "secret"},
		{"curl", "-H", "Authorization: Bearer abc"},
		{"app", "--password=hunter2"},
		{"app", "https://user:pass@example.com/api"},
	} {
		if !hasSensitiveRestartArgs(args) {
			t.Fatalf("sensitive args were considered restart-safe: %#v", args)
		}
	}
	if hasSensitiveRestartArgs([]string{"/usr/bin/sleep", "30"}) {
		t.Fatal("ordinary args incorrectly treated as sensitive")
	}
}

func TestSafeService(t *testing.T) {
	for _, u := range []string{"nginx.service", "x-ui.service", "my-app@1.service", "nlm-managed-123.service"} {
		if !safeService(u) {
			t.Fatalf("expected safe service %q", u)
		}
	}
	for _, u := range []string{"ssh.service", "sshd.service", "docker.service", "containerd.service", "nodelume-agent.service", "../evil.service", "evil;rm.service"} {
		if safeService(u) {
			t.Fatalf("expected protected/invalid service %q", u)
		}
	}
}

func TestVersionAndRepoValidation(t *testing.T) {
	if !validVersion("1.0.0") || !validVersion("v10.20.30") {
		t.Fatal("valid version rejected")
	}
	if validVersion("1.0") || validVersion("1.0.0-beta") {
		t.Fatal("invalid version accepted")
	}
	if !validRepo("chenb1522/nodelume") {
		t.Fatal("valid repo rejected")
	}
	if validRepo("owner/repo/extra") || validRepo("owner/repo;bad") {
		t.Fatal("invalid repo accepted")
	}
}

func TestValidateServerURL(t *testing.T) {
	good := []string{"https://monitor.example.com", "http://127.0.0.1:8080", "http://localhost:8080", "http://203.0.113.9:8080"}
	for _, u := range good {
		if err := validateServerURL(u, false); err != nil {
			t.Fatalf("expected URL %q to be allowed: %v", u, err)
		}
	}
	for _, u := range []string{"ftp://example.com", "not-a-url", ""} {
		if err := validateServerURL(u, false); err == nil {
			t.Fatalf("invalid URL %q accepted", u)
		}
	}
}

func TestProcessExitedTreatsZombie(t *testing.T) {
	cmd := exec.Command("/usr/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("sleep unavailable: %v", err)
	}
	pid := cmd.Process.Pid
	defer cmd.Wait()
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if processExited(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("zombie/exited process %d was not recognized as exited", pid)
}

func TestSaveConfigUsesDirectoryOwnerAnd0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := saveConfig(path, Config{Server: "http://127.0.0.1:8080", NodeID: "node-test", Secret: "secret-test"}); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0600 {
		t.Fatalf("config mode = %o, want 0600", fileInfo.Mode().Perm())
	}
	ds, dok := dirInfo.Sys().(*syscall.Stat_t)
	fs, fok := fileInfo.Sys().(*syscall.Stat_t)
	if dok && fok && (ds.Uid != fs.Uid || ds.Gid != fs.Gid) {
		t.Fatalf("config owner %d:%d does not match directory %d:%d", fs.Uid, fs.Gid, ds.Uid, ds.Gid)
	}
}

func TestManagedUnitAndShellQuote(t *testing.T) {
	if !isManagedUnit("nlm-managed-123.service") || isManagedUnit("nodelume-agent.service") || isManagedUnit("nlm-managed-bad") {
		t.Fatal("managed unit detection failed")
	}
	if got, want := quoteShellArg("a'b"), "'a'\\''b'"; got != want {
		t.Fatalf("quoteShellArg = %q, want %q", got, want)
	}
}

func TestBetterDiskMount(t *testing.T) {
	if !betterDiskMount("/", "/var/lib/nodelume-agent") {
		t.Fatal("root mount should win over sandbox/bind alias")
	}
	if betterDiskMount("/var/tmp", "/data") {
		t.Fatal("noise mount must not replace a real data mount")
	}
}

func TestHeartbeatForServerLegacyCompatibility(t *testing.T) {
	hb := Heartbeat{CPUFreqMHz: 2500, SwapUsed: 1, SwapTotal: 2, ReportIntervalSec: 10}
	legacy, err := json.Marshal(heartbeatForServer(hb, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cpu_freq_mhz", "swap_used", "swap_total", "report_interval_sec"} {
		if bytes.Contains(legacy, []byte(`"`+key+`"`)) {
			t.Fatalf("legacy heartbeat unexpectedly contains %q: %s", key, legacy)
		}
	}
	extended, err := json.Marshal(heartbeatForServer(hb, true))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cpu_freq_mhz", "swap_used", "swap_total", "report_interval_sec"} {
		if !bytes.Contains(extended, []byte(`"`+key+`"`)) {
			t.Fatalf("extended heartbeat missing %q: %s", key, extended)
		}
	}
}
