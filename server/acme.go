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
	"time"
)

type HTTPSRuntime struct {
	challenges  map[string]string
	challengeMu sync.RWMutex
}

type CertStatus struct {
	Mode      string `json:"mode"`
	Source    string `json:"source,omitempty"`
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
	if len(d) < 4 || len(d) > 253 || strings.ContainsAny(d, "/:") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
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
			if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')) {
				return false
			}
		}
	}
	return true
}

func (a *App) checkHTTPSSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
		Mode   string `json:"mode,omitempty"`
	}
	if !decodeJSON(w, r, &in, 1<<14) {
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	if in.Mode == "" {
		in.Mode = "builtin"
	}
	if in.Mode != "off" && !validDomain(in.Domain) {
		jsonErrorCode(w, "INVALID_DOMAIN", "域名格式无效", "请输入已解析到当前 Server 的域名", 400)
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
		ln, err := net.Listen("tcp", ":80")
		if err != nil {
			jsonErrorCode(w, "ACME_PORT_IN_USE", "HTTP-01 需要公网 80 端口，但当前无法监听", err.Error(), 409)
			return
		}
		_ = ln.Close()
	}
	writeJSON(w, 200, out)
}

// applyHTTPSSettings is the public "申请证书" endpoint. The user only supplies a domain;
// HTTP-01 and ACME details stay internal. The certificate is activated on the configured
// NodeLume listen port after a controlled Server restart.
func (a *App) applyHTTPSSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
		Mode   string `json:"mode,omitempty"`
	}
	if !decodeJSON(w, r, &in, 1<<14) {
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	if in.Mode == "" {
		in.Mode = "builtin"
	}
	if in.Mode == "off" {
		a.mu.Lock()
		old := a.state.Settings.Domain
		a.state.Settings.Domain = ""
		a.state.Settings.HTTPSMode = "off"
		a.state.Settings.CertificateSource = ""
		a.auditLocked(a.remoteIP(r), "https_apply", "", old+" -> off", "success")
		err := a.saveLocked()
		a.mu.Unlock()
		if err != nil {
			jsonError(w, "save failed", 500)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "restart_required": true})
		return
	}
	if in.Mode != "builtin" || !validDomain(in.Domain) {
		jsonErrorCode(w, "INVALID_DOMAIN", "域名格式无效", "请输入有效域名", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := a.ensureManagedCertificate(ctx, in.Domain, true); err != nil {
		a.audit(a.remoteIP(r), "certificate_issue", "", in.Domain, "failed: "+err.Error())
		jsonErrorCode(w, "ACME_CHALLENGE_FAILED", err.Error(), "检查域名 DNS、防火墙和公网 80 端口", 409)
		return
	}
	a.mu.Lock()
	old := a.state.Settings.Domain
	a.state.Settings.Domain = in.Domain
	a.state.Settings.HTTPSMode = "builtin"
	a.state.Settings.CertificateSource = "acme"
	a.auditLocked(a.remoteIP(r), "certificate_issue", "", fmt.Sprintf("%s -> %s", old, in.Domain), "success")
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonErrorCode(w, "CERT_SAVE_FAILED", "证书已签发但配置保存失败", err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "certificate": a.certificateStatus(), "restart_required": true, "access_url": domainAccessURL(in.Domain, a.activeListen)})
}

func (a *App) checkCertificate(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	mode, domain, source := a.state.Settings.HTTPSMode, a.state.Settings.Domain, a.state.Settings.CertificateSource
	a.mu.RUnlock()
	if mode != "builtin" || domain == "" {
		writeJSON(w, 200, a.certificateStatus())
		return
	}
	if source == "acme" {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		if err := a.ensureManagedCertificate(ctx, domain, false); err != nil {
			a.audit(a.remoteIP(r), "certificate_check", "", domain, "failed: "+err.Error())
			jsonErrorCode(w, "ACME_CHALLENGE_FAILED", err.Error(), "检查 DNS、防火墙和公网 80 端口", 503)
			return
		}
	}
	a.audit(a.remoteIP(r), "certificate_check", "", domain, "success")
	writeJSON(w, 200, a.certificateStatus())
}
func (a *App) autoRenewCertificate() {
	a.mu.RLock()
	mode, domain, source := a.state.Settings.HTTPSMode, a.state.Settings.Domain, a.state.Settings.CertificateSource
	a.mu.RUnlock()
	if mode != "builtin" || domain == "" || source != "acme" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := a.ensureManagedCertificate(ctx, domain, false); err != nil {
		log.Printf("certificate renewal check: %v", err)
	}
}

func (a *App) certificateStatus() CertStatus {
	a.mu.RLock()
	mode, domain, source := a.state.Settings.HTTPSMode, a.state.Settings.Domain, a.state.Settings.CertificateSource
	a.mu.RUnlock()
	s := CertStatus{Mode: mode, Source: source, Domain: domain, Status: "not_managed", AutoRenew: mode == "builtin" && source == "acme"}
	if mode != "builtin" || domain == "" {
		return s
	}
	certPath, keyPath := a.certPaths(domain)
	cert, err := loadTLSCertificate(certPath, keyPath)
	if err != nil {
		s.Status = "missing"
		s.Error = err.Error()
		return s
	}
	if len(cert.Certificate) == 0 {
		s.Status = "invalid"
		return s
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		s.Status = "invalid"
		s.Error = err.Error()
		return s
	}
	if err = leaf.VerifyHostname(domain); err != nil {
		s.Status = "invalid"
		s.Error = err.Error()
		return s
	}
	s.NotAfter = leaf.NotAfter.Unix()
	s.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	if time.Now().After(leaf.NotAfter) {
		s.Status = "expired"
	} else if s.AutoRenew && s.DaysLeft < 30 {
		s.Status = "renewal_due"
	} else {
		s.Status = "valid"
	}
	return s
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

func (a *App) ensureManagedCertificate(ctx context.Context, domain string, force bool) error {
	certPath, keyPath := a.certPaths(domain)
	if !force {
		if c, err := loadTLSCertificate(certPath, keyPath); err == nil && len(c.Certificate) > 0 {
			if leaf, _ := x509.ParseCertificate(c.Certificate[0]); leaf != nil && leaf.VerifyHostname(domain) == nil && time.Until(leaf.NotAfter) > 30*24*time.Hour {
				return nil
			}
		}
	}
	rt := &HTTPSRuntime{challenges: map[string]string{}}
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("HTTP-01 无法监听公网 80 端口: %w", err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		if token == r.URL.Path {
			http.NotFound(w, r)
			return
		}
		rt.challengeMu.RLock()
		v, ok := rt.challenges[token]
		rt.challengeMu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, v)
	})}
	go func() {
		if er := srv.Serve(ln); er != nil && er != http.ErrServerClosed {
			log.Printf("ACME HTTP-01 listener: %v", er)
		}
	}()
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
		_ = ln.Close()
	}()
	certPEM, keyPEM, err := a.obtainACMECertificate(ctx, domain, rt)
	if err != nil {
		return err
	}
	return installCertificatePair(certPath, keyPath, certPEM, keyPEM)
}

func installCertificatePair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return err
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("certificate/key mismatch: %w", err)
	}
	suffix := fmt.Sprintf(".%d.tmp", time.Now().UnixNano())
	ct, kt := certPath+suffix, keyPath+suffix
	cleanup := func() { _ = os.Remove(ct); _ = os.Remove(kt) }
	defer cleanup()
	writeTmp := func(path string, b []byte) error {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if _, err = f.Write(b); err == nil {
			err = f.Sync()
		}
		ce := f.Close()
		if err == nil {
			err = ce
		}
		return err
	}
	if err := writeTmp(ct, certPEM); err != nil {
		return err
	}
	if err := writeTmp(kt, keyPEM); err != nil {
		return err
	}
	if _, err := tls.LoadX509KeyPair(ct, kt); err != nil {
		return err
	}
	oldCert, certErr := os.ReadFile(certPath)
	oldKey, keyErr := os.ReadFile(keyPath)
	if err := os.Rename(ct, certPath); err != nil {
		return err
	}
	if err := os.Rename(kt, keyPath); err != nil {
		if certErr == nil {
			_ = atomicWrite(certPath, oldCert, 0600)
		} else {
			_ = os.Remove(certPath)
		}
		return err
	}
	if d, er := os.Open(filepath.Dir(certPath)); er == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	_ = oldKey
	_ = keyErr
	return nil
}

// Compatibility wrappers: built-in HTTPS no longer opens a second :443 listener.
func (a *App) startBuiltinHTTPS(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return a.ensureManagedCertificate(ctx, domain, false)
}
func (a *App) startBuiltinHTTPSContext(ctx context.Context, domain string) error {
	return a.ensureManagedCertificate(ctx, domain, false)
}
func (a *App) stopBuiltinHTTPS() {}
func (a *App) ensureCertificate(ctx context.Context, domain string, force bool) error {
	return a.ensureManagedCertificate(ctx, domain, force)
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

func (a *App) importCertificate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain      string `json:"domain"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	if !decodeJSON(w, r, &in, 3<<20) {
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	if in.Domain == "" {
		a.mu.RLock()
		in.Domain = a.state.Settings.Domain
		a.mu.RUnlock()
	}
	if !validDomain(in.Domain) {
		jsonErrorCode(w, "CERT_DOMAIN_MISMATCH", "请先填写有效域名", "证书必须对应将要使用的域名", 400)
		return
	}
	certPEM, keyPEM := []byte(in.Certificate), []byte(in.PrivateKey)
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		jsonErrorCode(w, "CERT_PARSE_FAILED", "证书和私钥不能为空", "请提供 Full Chain 和私钥 PEM", 400)
		return
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		jsonErrorCode(w, "CERT_KEY_MISMATCH", "证书与私钥不匹配", err.Error(), 400)
		return
	}
	if len(pair.Certificate) == 0 {
		jsonErrorCode(w, "CERT_PARSE_FAILED", "证书内容为空", "请提供有效 PEM", 400)
		return
	}
	certs := make([]*x509.Certificate, 0, len(pair.Certificate))
	for _, der := range pair.Certificate {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			jsonErrorCode(w, "CERT_PARSE_FAILED", "证书链解析失败", e.Error(), 400)
			return
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	if err = leaf.VerifyHostname(in.Domain); err != nil {
		jsonErrorCode(w, "CERT_DOMAIN_MISMATCH", "证书不包含配置域名", err.Error(), 400)
		return
	}
	if time.Now().After(leaf.NotAfter) {
		jsonErrorCode(w, "CERT_EXPIRED", "证书已过期", "请导入有效证书", 400)
		return
	}
	for i := 0; i+1 < len(certs); i++ {
		if err = certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			jsonErrorCode(w, "CERT_CHAIN_INCOMPLETE", "证书链顺序或签名无效", err.Error(), 400)
			return
		}
	}
	certPath, keyPath := a.certPaths(in.Domain)
	oldCert, oldCertErr := os.ReadFile(certPath)
	oldKey, oldKeyErr := os.ReadFile(keyPath)
	if err = installCertificatePair(certPath, keyPath, certPEM, keyPEM); err != nil {
		jsonErrorCode(w, "CERT_SAVE_FAILED", "证书保存失败", err.Error(), 500)
		return
	}
	restorePair := func() {
		if oldCertErr == nil && oldKeyErr == nil {
			_ = installCertificatePair(certPath, keyPath, oldCert, oldKey)
		} else {
			_ = os.Remove(certPath)
			_ = os.Remove(keyPath)
		}
	}
	a.mu.Lock()
	oldDomain, oldMode, oldSource := a.state.Settings.Domain, a.state.Settings.HTTPSMode, a.state.Settings.CertificateSource
	a.state.Settings.Domain = in.Domain
	a.state.Settings.HTTPSMode = "builtin"
	a.state.Settings.CertificateSource = "manual"
	a.auditLocked(a.remoteIP(r), "certificate_import", "", in.Domain, "success")
	err = a.saveLocked()
	if err != nil {
		a.state.Settings.Domain, a.state.Settings.HTTPSMode, a.state.Settings.CertificateSource = oldDomain, oldMode, oldSource
	}
	a.mu.Unlock()
	if err != nil {
		restorePair()
		jsonErrorCode(w, "CERT_SAVE_FAILED", "配置保存失败，已恢复原证书", err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "not_after": leaf.NotAfter.Unix(), "domain": in.Domain, "source": "manual", "restart_required": true, "access_url": domainAccessURL(in.Domain, a.activeListen)})
}
