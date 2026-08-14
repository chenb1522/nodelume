package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type agentAuthFailure struct {
	Code, Reason, Action string
	Status               int
}

func (a *App) authAgentDetailed(r *http.Request) (string, *agentAuthFailure) {
	id := strings.TrimSpace(r.Header.Get("X-Node-ID"))
	if id != "" {
		tsRaw := strings.TrimSpace(r.Header.Get("X-Timestamp"))
		nonce := strings.TrimSpace(r.Header.Get("X-Nonce"))
		sig := strings.TrimSpace(r.Header.Get("X-Signature"))
		if tsRaw == "" || nonce == "" || sig == "" {
			return "", &agentAuthFailure{"AUTH_INVALID", "Agent 认证头不完整", "请检查 Agent 版本和配置", http.StatusUnauthorized}
		}
		ts, err := strconv.ParseInt(tsRaw, 10, 64)
		if err != nil {
			return "", &agentAuthFailure{"AUTH_INVALID", "Agent 时间戳格式无效", "请检查 Agent 版本", http.StatusUnauthorized}
		}
		skew := time.Now().Unix() - ts
		if abs64(skew) > 60 {
			return "", &agentAuthFailure{"CLOCK_SKEW", "Agent 与 Server 时间偏差超过 60 秒", "请同步 Agent 与 Server 系统时间", http.StatusUnauthorized}
		}
		a.mu.RLock()
		n := a.state.Nodes[id]
		a.mu.RUnlock()
		if n == nil || !n.Registered {
			return "", &agentAuthFailure{"NODE_REVOKED", "节点身份已被 Server 吊销或不存在", "请重新绑定 Server", http.StatusUnauthorized}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			return "", &agentAuthFailure{"AUTH_INVALID", "无法读取认证请求", "请重试", http.StatusBadRequest}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		bh := sha256.Sum256(body)
		msg := r.Method + "\n" + r.URL.RequestURI() + "\n" + tsRaw + "\n" + nonce + "\n" + hex.EncodeToString(bh[:])
		valid := func(secret string) bool {
			if secret == "" {
				return false
			}
			m := hmac.New(sha256.New, []byte(secret))
			_, _ = m.Write([]byte(msg))
			want := hex.EncodeToString(m.Sum(nil))
			return subtle.ConstantTimeCompare([]byte(want), []byte(sig)) == 1
		}
		accepted := valid(n.AgentSecret)
		if !accepted && n.PreviousAgentSecret != "" && n.PreviousSecretExpiresAt >= time.Now().Unix() {
			accepted = valid(n.PreviousAgentSecret)
		}
		if !accepted {
			return "", &agentAuthFailure{"AUTH_SIGNATURE_INVALID", "Agent 请求签名无效", "请检查节点身份或重新绑定 Server", http.StatusUnauthorized}
		}
		key := id + ":" + nonce
		now := time.Now().Unix()
		a.noncesMu.Lock()
		defer a.noncesMu.Unlock()
		for k, v := range a.nonces {
			if now-v > 120 {
				delete(a.nonces, k)
			}
		}
		if _, exists := a.nonces[key]; exists {
			return "", &agentAuthFailure{"REPLAY_DETECTED", "检测到重复 Agent 请求", "请检查网络重放或 Agent 状态", http.StatusConflict}
		}
		if len(a.nonces) >= 4096 { // deterministic bounded eviction: remove expired already; then trim arbitrary old entries.
			trimmed := 0
			for k := range a.nonces {
				delete(a.nonces, k)
				trimmed++
				if trimmed >= 2048 {
					break
				}
			}
		}
		a.nonces[key] = now
		return id, nil
	}
	// v1.0.0 compatibility while upgrading existing installations.
	v := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	i := strings.IndexByte(v, '.')
	if i <= 0 {
		return "", &agentAuthFailure{"AUTH_REQUIRED", "Agent 未提供有效认证信息", "请升级或重新绑定 Agent", http.StatusUnauthorized}
	}
	id, secret := v[:i], v[i+1:]
	a.mu.RLock()
	n := a.state.Nodes[id]
	a.mu.RUnlock()
	if n == nil || !n.Registered {
		return "", &agentAuthFailure{"NODE_REVOKED", "节点身份已被 Server 吊销或不存在", "请重新绑定 Server", http.StatusUnauthorized}
	}
	got := hashString(secret)
	if n.SecretHash == "" || subtle.ConstantTimeCompare([]byte(got), []byte(n.SecretHash)) != 1 {
		return "", &agentAuthFailure{"AUTH_SIGNATURE_INVALID", "Agent 身份验证失败", "请升级或重新绑定 Agent", http.StatusUnauthorized}
	}
	return id, nil
}

// authAgent is kept for internal tests and v1.0.0-compatible call sites.
func (a *App) authAgent(r *http.Request) (string, bool) {
	id, fail := a.authAgentDetailed(r)
	return id, fail == nil
}
