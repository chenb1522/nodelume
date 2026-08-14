package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestAgentHMACAndReplay(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	a := &App{state: PersistedState{Nodes: map[string]*PersistNode{"n1": {ID: "n1", Registered: true, AgentSecret: secret}}}, nonces: map[string]int64{}}
	body := []byte(`{"x":1}`)
	mk := func(ts int64, nonce string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://x/api/agent/heartbeat", bytes.NewReader(body))
		tsv := strconv.FormatInt(ts, 10)
		bh := sha256.Sum256(body)
		msg := "POST\n/api/agent/heartbeat\n" + tsv + "\n" + nonce + "\n" + hex.EncodeToString(bh[:])
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte(msg))
		r.Header.Set("X-Node-ID", "n1")
		r.Header.Set("X-Timestamp", tsv)
		r.Header.Set("X-Nonce", nonce)
		r.Header.Set("X-Signature", hex.EncodeToString(m.Sum(nil)))
		if _, ok := a.authAgent(r); !ok {
			t.Fatal("valid HMAC rejected")
		}
		return httptest.NewRecorder()
	}
	_ = mk(time.Now().Unix(), "abc123")
	r := httptest.NewRequest("POST", "http://x/api/agent/heartbeat", bytes.NewReader(body))
	tsv := strconv.FormatInt(time.Now().Unix(), 10)
	bh := sha256.Sum256(body)
	msg := "POST\n/api/agent/heartbeat\n" + tsv + "\nabc123\n" + hex.EncodeToString(bh[:])
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(msg))
	r.Header.Set("X-Node-ID", "n1")
	r.Header.Set("X-Timestamp", tsv)
	r.Header.Set("X-Nonce", "abc123")
	r.Header.Set("X-Signature", hex.EncodeToString(m.Sum(nil)))
	if _, ok := a.authAgent(r); ok {
		t.Fatal("replay nonce accepted")
	}
}
