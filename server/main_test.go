package main

import (
	"testing"
	"time"
)

func TestRingCapacityAndSince(t *testing.T) {
	r := NewRing(3)
	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		r.Add(MetricPoint{T: now + int64(i), CPU: float32(i)})
	}
	all := r.all()
	if len(all) != 3 || all[0].CPU != 2 || all[2].CPU != 4 {
		t.Fatalf("unexpected ring contents: %#v", all)
	}
	got := r.Since(now + 4)
	if len(got) != 1 || got[0].CPU != 4 {
		t.Fatalf("unexpected Since result: %#v", got)
	}
}

func TestAdminPathValidation(t *testing.T) {
	good := []string{"/abc12", "/secure_path", "/A-b_123"}
	for _, p := range good {
		if !validAdminPath(p) {
			t.Fatalf("expected valid path %q", p)
		}
	}
	bad := []string{"/", "/abc", "/api-test", "/has/slash", "/bad?x"}
	for _, p := range bad {
		if validAdminPath(p) {
			t.Fatalf("expected invalid path %q", p)
		}
	}
}

func TestPasswordHash(t *testing.T) {
	rec := makePassword("NodeLume-Test-Password-123")
	if !checkPassword("NodeLume-Test-Password-123", rec) {
		t.Fatal("correct password rejected")
	}
	if checkPassword("wrong-password", rec) {
		t.Fatal("wrong password accepted")
	}
}

func TestVersionCompare(t *testing.T) {
	if compareVersion("1.0.0", "1.0.1") >= 0 {
		t.Fatal("version ordering failed")
	}
	if compareVersion("v1.2.0", "1.1.9") <= 0 {
		t.Fatal("version ordering failed")
	}
	if compareVersion("1.0.0", "v1.0.0") != 0 {
		t.Fatal("version equality failed")
	}
}
