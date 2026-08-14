package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogWriterClearSwitchesHandle(t *testing.T) {
	dir := t.TempDir()
	w, err := newLogWriter(dir, 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err = w.Write([]byte("before\n")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "server-old.log"), []byte("history\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = w.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("after\n")); err != nil {
		t.Fatal(err)
	}
	got, _, err := w.Tail(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("unexpected active log: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "server.log" {
		t.Fatalf("unexpected files after clear: %v", entries)
	}
}

func TestLogWriterSizeRotateKeepsActiveHandle(t *testing.T) {
	dir := t.TempDir()
	w, err := newLogWriter(dir, 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err = w.Write([]byte("old\n")); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	w.size = 10 << 20
	w.mu.Unlock()
	if _, err = w.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	got, _, err := w.Tail(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "new") {
		t.Fatalf("new active log missing: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected rotated history plus active log")
	}
}
