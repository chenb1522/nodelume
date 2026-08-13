package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type HTTPSRuntime struct {
	mu            sync.RWMutex
	domain        string
	cert          atomic.Pointer[tls.Certificate]
	challenges    map[string]string
	challengeMu   sync.RWMutex
	httpListener  net.Listener
	httpsListener net.Listener
	httpServer    *http.Server
	httpsServer   *http.Server
}

type CertStatus struct {
	Mode      string `json:"mode"`
	Domain    string `json:"domain"`
	Status    string `json:"status"`
	NotAfter  int64  `json:"not_after,omitempty"`
	DaysLeft  int    `json:"days_left,omitempty"`
	AutoRenew bool   `json:"auto_renew"`
	Error     string `json:"error,omitempty"`
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}
type acmeAccountState struct {
	KID string `json:"kid"`
}
type acmeOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}
type acmeAuthz struct {
	Status     string                                      `json:"status"`
	Challenges []struct{ Type, URL, Token, Status string } `json:"challenges"`
}

type jwkEC struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type acmeClient struct {
	http *http.Client
	dir  acmeDirectory
	key  *ecdsa.PrivateKey
	kid  string
}

func validDomain(d string) bool {
	d = strings.TrimSpace(strings.ToLower(d))
	if len(d) < 4 || len(d) > 253 || strings.Contains(d, "/") || strings.Contains(d, ":") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z') {
				return false
			}
		}
	}
	return true
}

func (a *App) checkHTTPSSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
		Mode   string `json:"mode"`
	}
	if !decodeJSON(w, r, &in, 1<<14) {
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	if in.Mode != "off" && !validDomain(in.Domain) {
		jsonError(w, "invalid domain", 400)
		return
	}
	if in.Mode != "off" && in.Mode != "proxy" && in.Mode != "builtin" {
		jsonError(w, "invalid HTTPS mode", 400)
		return
	}
	out := map[string]any{"ok": true, "domain": in.Domain, "mode": in.Mode}
	if in.Domain != "" {
		if ips, err := net.DefaultResolver.LookupHost(r.Context(), in.Domain); err == nil {
			out["dns_addresses"] = ips
		} else {
			out["dns_warning"] = err.Error()
		}
	}
	if in.Mode == "builtin" {
		a.httpsMu.Lock()
		active := a.httpsRuntime != nil
		a.httpsMu.Unlock()
		if !active {
			for _, addr := range []string{":80", ":443"} {
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					jsonError(w, "port check failed for "+addr+": "+err.Error(), 409)
					return
				}
				ln.Close()
			}
		}
	}
	writeJSON(w, 200, out)
}

func (a *App) applyHTTPSSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
		Mode   string `json:"mode"`
	}
	if !decodeJSON(w, r, &in, 1<<14) {
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	if in.Mode != "off" && !validDomain(in.Domain) {
		jsonError(w, "invalid domain", 400)
		return
	}
	if in.Mode != "off" && in.Mode != "proxy" && in.Mode != "builtin" {
		jsonError(w, "invalid HTTPS mode", 400)
		return
	}
	if in.Mode == "builtin" {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		if err := a.startBuiltinHTTPSContext(ctx, in.Domain); err != nil {
			a.audit(a.remoteIP(r), "https_apply", "", in.Domain, "failed: "+err.Error())
			jsonError(w, "built-in HTTPS was not changed: "+err.Error(), 409)
			return
		}
	} else {
		a.stopBuiltinHTTPS()
	}
	ip := a.remoteIP(r)
	a.mu.Lock()
	old := a.state.Settings.Domain
	a.state.Settings.Domain = in.Domain
	a.state.Settings.HTTPSMode = in.Mode
	a.auditLocked(ip, "https_apply", "", fmt.Sprintf("%s -> %s (%s)", old, in.Domain, in.Mode), "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonError(w, "save failed", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "settings": map[string]any{"domain": in.Domain, "https_mode": in.Mode}, "certificate": a.certificateStatus()})
}

func (a *App) checkCertificate(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	mode, domain := a.state.Settings.HTTPSMode, a.state.Settings.Domain
	a.mu.RUnlock()
	if mode != "builtin" || domain == "" {
		writeJSON(w, 200, a.certificateStatus())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := a.ensureCertificate(ctx, domain, false); err != nil {
		a.audit(a.remoteIP(r), "certificate_check", "", domain, "failed: "+err.Error())
		jsonError(w, err.Error(), 503)
		return
	}
	a.audit(a.remoteIP(r), "certificate_check", "", domain, "success")
	writeJSON(w, 200, a.certificateStatus())
}
func (a *App) autoRenewCertificate() {
	a.mu.RLock()
	mode, domain := a.state.Settings.HTTPSMode, a.state.Settings.Domain
	a.mu.RUnlock()
	if mode != "builtin" || domain == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := a.ensureCertificate(ctx, domain, false); err != nil {
		log.Printf("certificate renewal check: %v", err)
	}
}

func (a *App) certificateStatus() CertStatus {
	a.mu.RLock()
	mode, domain := a.state.Settings.HTTPSMode, a.state.Settings.Domain
	a.mu.RUnlock()
	s := CertStatus{Mode: mode, Domain: domain, Status: "not_managed", AutoRenew: mode == "builtin"}
	if mode != "builtin" || domain == "" {
		return s
	}
	certPath, _ := a.certPaths(domain)
	b, err := os.ReadFile(certPath)
	if err != nil {
		s.Status = "missing"
		s.Error = err.Error()
		return s
	}
	block, _ := pem.Decode(b)
	if block == nil {
		s.Status = "invalid"
		return s
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.Status = "invalid"
		s.Error = err.Error()
		return s
	}
	s.NotAfter = c.NotAfter.Unix()
	s.DaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
	if time.Now().After(c.NotAfter) {
		s.Status = "expired"
	} else if s.DaysLeft < 30 {
		s.Status = "renewal_due"
	} else {
		s.Status = "valid"
	}
	return s
}

func (a *App) startBuiltinHTTPS(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return a.startBuiltinHTTPSContext(ctx, domain)
}
func (a *App) startBuiltinHTTPSContext(ctx context.Context, domain string) error {
	a.httpsMu.Lock()
	defer a.httpsMu.Unlock()
	if a.httpsRuntime != nil {
		rt := a.httpsRuntime
		rt.mu.RLock()
		same := rt.domain == domain
		rt.mu.RUnlock()
		if same {
			return a.ensureCertificateWithRuntime(ctx, domain, false, rt)
		}
		if err := a.ensureCertificateWithRuntime(ctx, domain, true, rt); err != nil {
			return err
		}
		rt.mu.Lock()
		rt.domain = domain
		rt.mu.Unlock()
		return nil
	}
	l80, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("listen port 80: %w", err)
	}
	l443, err := net.Listen("tcp", ":443")
	if err != nil {
		l80.Close()
		return fmt.Errorf("listen port 443: %w", err)
	}
	rt := &HTTPSRuntime{domain: domain, challenges: map[string]string{}, httpListener: l80, httpsListener: l443}
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
			rt.challengeMu.RLock()
			v, ok := rt.challenges[token]
			rt.challengeMu.RUnlock()
			if ok {
				w.Header().Set("Content-Type", "text/plain")
				io.WriteString(w, v)
				return
			}
		}
		rt.mu.RLock()
		d := rt.domain
		rt.mu.RUnlock()
		http.Redirect(w, r, "https://"+d+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
	rt.httpServer = &http.Server{Handler: redirect, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if er := rt.httpServer.Serve(l80); er != nil && er != http.ErrServerClosed {
			log.Printf("ACME HTTP listener: %v", er)
		}
	}()
	if err := a.ensureCertificateWithRuntime(ctx, domain, false, rt); err != nil {
		rt.httpServer.Close()
		l443.Close()
		return err
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c := rt.cert.Load()
		if c == nil {
			return nil, errors.New("certificate unavailable")
		}
		rt.mu.RLock()
		d := rt.domain
		rt.mu.RUnlock()
		if chi.ServerName != "" && !strings.EqualFold(chi.ServerName, d) {
			return nil, errors.New("unrecognized TLS hostname")
		}
		return c, nil
	}}
	rt.httpsServer = &http.Server{Handler: a.handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 65 * time.Second, TLSConfig: tlsCfg}
	go func() {
		tl := tls.NewListener(l443, tlsCfg)
		if er := rt.httpsServer.Serve(tl); er != nil && er != http.ErrServerClosed {
			log.Printf("HTTPS listener: %v", er)
		}
	}()
	a.httpsRuntime = rt
	return nil
}
func (a *App) stopBuiltinHTTPS() {
	a.httpsMu.Lock()
	rt := a.httpsRuntime
	a.httpsRuntime = nil
	a.httpsMu.Unlock()
	if rt != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if rt.httpServer != nil {
			_ = rt.httpServer.Shutdown(ctx)
		}
		if rt.httpsServer != nil {
			_ = rt.httpsServer.Shutdown(ctx)
		}
		if rt.httpListener != nil {
			_ = rt.httpListener.Close()
		}
		if rt.httpsListener != nil {
			_ = rt.httpsListener.Close()
		}
	}
}
func (a *App) ensureCertificate(ctx context.Context, domain string, force bool) error {
	a.httpsMu.Lock()
	rt := a.httpsRuntime
	a.httpsMu.Unlock()
	if rt == nil {
		return errors.New("built-in HTTPS listener is not active")
	}
	return a.ensureCertificateWithRuntime(ctx, domain, force, rt)
}
func (a *App) ensureCertificateWithRuntime(ctx context.Context, domain string, force bool, rt *HTTPSRuntime) error {
	certPath, keyPath := a.certPaths(domain)
	if !force {
		if cert, err := loadTLSCertificate(certPath, keyPath); err == nil {
			if len(cert.Certificate) > 0 {
				leaf, _ := x509.ParseCertificate(cert.Certificate[0])
				if leaf != nil && time.Until(leaf.NotAfter) > 30*24*time.Hour {
					rt.cert.Store(cert)
					return nil
				}
			}
		}
	}
	certPEM, keyPEM, err := a.obtainACMECertificate(ctx, domain, rt)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.acmeDir, 0700); err != nil {
		return err
	}
	if err := atomicWrite(certPath, certPEM, 0600); err != nil {
		return err
	}
	if err := atomicWrite(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	cert, err := loadTLSCertificate(certPath, keyPath)
	if err != nil {
		return err
	}
	rt.cert.Store(cert)
	return nil
}
func (a *App) certPaths(domain string) (string, string) {
	safe := strings.ReplaceAll(domain, "*", "wildcard")
	return filepath.Join(a.acmeDir, safe+".crt"), filepath.Join(a.acmeDir, safe+".key")
}
func loadTLSCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (a *App) obtainACMECertificate(ctx context.Context, domain string, rt *HTTPSRuntime) ([]byte, []byte, error) {
	directoryURL := envOr("NODELUME_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory")
	key, kid, err := a.loadOrCreateACMEAccount()
	if err != nil {
		return nil, nil, err
	}
	cli := &acmeClient{http: &http.Client{Timeout: 15 * time.Second}, key: key, kid: kid}
	if err := cli.getDirectory(ctx, directoryURL); err != nil {
		return nil, nil, err
	}
	if cli.kid == "" {
		if err := cli.createAccount(ctx); err != nil {
			return nil, nil, err
		}
		if err := a.saveACMEKID(cli.kid); err != nil {
			return nil, nil, err
		}
	}
	orderURL, order, err := cli.newOrder(ctx, domain)
	if err != nil {
		return nil, nil, err
	}
	thumb, err := cli.thumbprint()
	if err != nil {
		return nil, nil, err
	}
	for _, authURL := range order.Authorizations {
		var az acmeAuthz
		if _, err := cli.postAsGet(ctx, authURL, &az); err != nil {
			return nil, nil, err
		}
		if az.Status == "valid" {
			continue
		}
		var ch *struct{ Type, URL, Token, Status string }
		for i := range az.Challenges {
			if az.Challenges[i].Type == "http-01" {
				ch = &az.Challenges[i]
				break
			}
		}
		if ch == nil {
			return nil, nil, errors.New("ACME authorization has no http-01 challenge")
		}
		keyAuth := ch.Token + "." + thumb
		rt.challengeMu.Lock()
		rt.challenges[ch.Token] = keyAuth
		rt.challengeMu.Unlock()
		_, err := cli.signed(ctx, ch.URL, []byte(`{}`), nil)
		if err != nil {
			return nil, nil, err
		}
		deadline := time.Now().Add(70 * time.Second)
		for {
			if time.Now().After(deadline) {
				return nil, nil, errors.New("ACME authorization timed out")
			}
			time.Sleep(2 * time.Second)
			var cur acmeAuthz
			if _, err := cli.postAsGet(ctx, authURL, &cur); err != nil {
				return nil, nil, err
			}
			if cur.Status == "valid" {
				break
			}
			if cur.Status == "invalid" {
				return nil, nil, errors.New("ACME HTTP-01 validation failed")
			}
		}
		rt.challengeMu.Lock()
		delete(rt.challenges, ch.Token)
		rt.challengeMu.Unlock()
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}}, certKey)
	if err != nil {
		return nil, nil, err
	}
	payload, _ := json.Marshal(map[string]string{"csr": b64(csrDER)})
	if _, err := cli.signed(ctx, order.Finalize, payload, nil); err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(70 * time.Second)
	for {
		if time.Now().After(deadline) {
			return nil, nil, errors.New("ACME order timed out")
		}
		time.Sleep(2 * time.Second)
		var cur acmeOrder
		if _, err := cli.postAsGet(ctx, orderURL, &cur); err != nil {
			return nil, nil, err
		}
		if cur.Status == "valid" && cur.Certificate != "" {
			certBody, err := cli.postAsGetRaw(ctx, cur.Certificate)
			if err != nil {
				return nil, nil, err
			}
			keyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
			if err != nil {
				return nil, nil, err
			}
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
			return certBody, keyPEM, nil
		}
		if cur.Status == "invalid" {
			return nil, nil, errors.New("ACME order became invalid")
		}
	}
}

func (a *App) loadOrCreateACMEAccount() (*ecdsa.PrivateKey, string, error) {
	if err := os.MkdirAll(a.acmeDir, 0700); err != nil {
		return nil, "", err
	}
	kp := filepath.Join(a.acmeDir, "account.key")
	sp := filepath.Join(a.acmeDir, "account.json")
	var key *ecdsa.PrivateKey
	if b, err := os.ReadFile(kp); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, "", errors.New("invalid ACME account key")
		}
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", err
		}
	} else {
		var er error
		key, er = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if er != nil {
			return nil, "", er
		}
		der, er := x509.MarshalECPrivateKey(key)
		if er != nil {
			return nil, "", er
		}
		if er = atomicWrite(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); er != nil {
			return nil, "", er
		}
	}
	kid := ""
	if b, err := os.ReadFile(sp); err == nil {
		var s acmeAccountState
		_ = json.Unmarshal(b, &s)
		kid = s.KID
	}
	return key, kid, nil
}
func (a *App) saveACMEKID(kid string) error {
	b, _ := json.Marshal(acmeAccountState{KID: kid})
	return atomicWrite(filepath.Join(a.acmeDir, "account.json"), b, 0600)
}

func (c *acmeClient) getDirectory(ctx context.Context, url string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("ACME directory HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&c.dir)
}
func (c *acmeClient) nonce(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, c.dir.NewNonce, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", errors.New("ACME server did not return a nonce")
	}
	return n, nil
}
func (c *acmeClient) jwk() jwkEC {
	return jwkEC{Crv: "P-256", Kty: "EC", X: b64(padded(c.key.PublicKey.X.Bytes(), 32)), Y: b64(padded(c.key.PublicKey.Y.Bytes(), 32))}
}
func (c *acmeClient) thumbprint() (string, error) {
	b, err := json.Marshal(c.jwk())
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return b64(h[:]), nil
}
func (c *acmeClient) createAccount(ctx context.Context) error {
	payload := []byte(`{"termsOfServiceAgreed":true}`)
	resp, err := c.signed(ctx, c.dir.NewAccount, payload, nil)
	if err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if loc == "" {
		return errors.New("ACME account response did not contain Location")
	}
	c.kid = loc
	return nil
}
func (c *acmeClient) newOrder(ctx context.Context, domain string) (string, acmeOrder, error) {
	payload, _ := json.Marshal(map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": domain}}})
	var out acmeOrder
	resp, err := c.signed(ctx, c.dir.NewOrder, payload, &out)
	if err != nil {
		return "", out, err
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", out, errors.New("ACME order missing Location")
	}
	return loc, out, nil
}
func (c *acmeClient) postAsGet(ctx context.Context, url string, out any) (*http.Response, error) {
	return c.signed(ctx, url, nil, out)
}
func (c *acmeClient) postAsGetRaw(ctx context.Context, url string) ([]byte, error) {
	resp, err := c.signed(ctx, url, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 2<<20))
}
func (c *acmeClient) signed(ctx context.Context, url string, payload []byte, out any) (*http.Response, error) {
	nonce, err := c.nonce(ctx)
	if err != nil {
		return nil, err
	}
	protected := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
	if c.kid != "" {
		protected["kid"] = c.kid
	} else {
		protected["jwk"] = c.jwk()
	}
	pb, _ := json.Marshal(protected)
	p64 := b64(payload)
	pheader := b64(pb)
	digest := sha256.Sum256([]byte(pheader + "." + p64))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := append(padded(r.Bytes(), 32), padded(s.Bytes(), 32)...)
	body, _ := json.Marshal(map[string]string{"protected": pheader, "payload": p64, "signature": b64(sig)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		return nil, fmt.Errorf("ACME HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
			resp.Body.Close()
			return nil, err
		}
	}
	return resp, nil
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func padded(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
