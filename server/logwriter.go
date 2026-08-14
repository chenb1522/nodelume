package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type logWriter struct {
	mu        sync.Mutex
	dir       string
	f         *os.File
	day       string
	size      int64
	retention int
	maxTotal  int64
	subs      map[chan string]struct{}
}

func newLogWriter(dir string, days, maxMiB int) (*logWriter, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	w := &logWriter{dir: dir, retention: days, maxTotal: int64(maxMiB) << 20, subs: map[chan string]struct{}{}}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}
func (w *logWriter) open() error {
	p := filepath.Join(w.dir, "server.log")
	f, e := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	st, _ := f.Stat()
	w.f = f
	w.size = st.Size()
	w.day = time.Now().Format("2006-01-02")
	return nil
}
func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if time.Now().Format("2006-01-02") != w.day || w.size >= 10<<20 {
		if e := w.rotate(); e != nil {
			return 0, e
		}
	}
	n, e := w.f.Write(p)
	w.size += int64(n)
	if n > 0 {
		line := string(p[:n])
		for ch := range w.subs {
			select {
			case ch <- line:
			default:
			}
		}
	}
	return n, e
}
func (w *logWriter) rotate() error {
	if w.f != nil {
		_ = w.f.Sync()
		_ = w.f.Close()
		dst := filepath.Join(w.dir, fmt.Sprintf("server-%s-%d.log", w.day, time.Now().Unix()))
		_ = os.Rename(filepath.Join(w.dir, "server.log"), dst)
	}
	if e := w.open(); e != nil {
		return e
	}
	w.cleanup()
	return nil
}
func (w *logWriter) cleanup() {
	es, _ := os.ReadDir(w.dir)
	type fi struct {
		p string
		t time.Time
		s int64
	}
	var xs []fi
	var total int64
	cut := time.Now().AddDate(0, 0, -w.retention)
	for _, e := range es {
		if e.IsDir() || e.Name() == "server.log" {
			continue
		}
		st, er := e.Info()
		if er != nil {
			continue
		}
		p := filepath.Join(w.dir, e.Name())
		if st.ModTime().Before(cut) {
			_ = os.Remove(p)
			continue
		}
		xs = append(xs, fi{p, st.ModTime(), st.Size()})
		total += st.Size()
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].t.Before(xs[j].t) })
	for _, x := range xs {
		if total <= w.maxTotal {
			break
		}
		_ = os.Remove(x.p)
		total -= x.s
	}
}
func (w *logWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	_ = w.f.Sync()
	return w.f.Close()
}

func (w *logWriter) Configure(days, maxMiB int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.retention = days
	w.maxTotal = int64(maxMiB) << 20
	w.cleanupLocked()
}
func (w *logWriter) cleanupLocked() { // caller holds lock
	es, _ := os.ReadDir(w.dir)
	type fi struct {
		p string
		t time.Time
		s int64
	}
	var xs []fi
	var total int64
	cut := time.Now().AddDate(0, 0, -w.retention)
	for _, e := range es {
		if e.IsDir() {
			continue
		}
		st, er := e.Info()
		if er != nil {
			continue
		}
		p := filepath.Join(w.dir, e.Name())
		if e.Name() != "server.log" && st.ModTime().Before(cut) {
			_ = os.Remove(p)
			continue
		}
		xs = append(xs, fi{p, st.ModTime(), st.Size()})
		total += st.Size()
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].t.Before(xs[j].t) })
	for _, x := range xs {
		if total <= w.maxTotal {
			break
		}
		if filepath.Base(x.p) == "server.log" {
			continue
		}
		_ = os.Remove(x.p)
		total -= x.s
	}
}
func (w *logWriter) Tail(max int64) (string, int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	p := filepath.Join(w.dir, "server.log")
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, nil
		}
		return "", 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	start := st.Size() - max
	if start < 0 {
		start = 0
	}
	_, _ = f.Seek(start, 0)
	b, err := io.ReadAll(f)
	return string(b), st.Size(), err
}
func (w *logWriter) Clear() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	active := filepath.Join(w.dir, "server.log")
	tmp := filepath.Join(w.dir, fmt.Sprintf(".server.log.clear-%d", time.Now().UnixNano()))
	if w.f != nil {
		_ = w.f.Sync()
		if err := w.f.Close(); err != nil {
			return err
		}
		w.f = nil
	}
	hadActive := false
	if _, err := os.Stat(active); err == nil {
		if err := os.Rename(active, tmp); err != nil {
			_ = w.open()
			return err
		}
		hadActive = true
	}
	if err := w.open(); err != nil {
		if hadActive {
			_ = os.Rename(tmp, active)
			_ = w.open()
		}
		return err
	}
	// A fresh active handle is live before deleting closed history files.
	es, _ := os.ReadDir(w.dir)
	for _, e := range es {
		if e.IsDir() || e.Name() == "server.log" {
			continue
		}
		_ = os.Remove(filepath.Join(w.dir, e.Name()))
	}
	return nil
}

func (w *logWriter) Subscribe() (<-chan string, func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch := make(chan string, 64)
	w.subs[ch] = struct{}{}
	return ch, func() {
		w.mu.Lock()
		if _, ok := w.subs[ch]; ok {
			delete(w.subs, ch)
			close(ch)
		}
		w.mu.Unlock()
	}
}
