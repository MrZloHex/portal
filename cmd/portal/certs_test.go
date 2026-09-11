package main

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type fakeManager struct {
	mu     sync.Mutex
	hellos []*tls.ClientHelloInfo
	fail   bool
}

func (f *fakeManager) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hellos = append(f.hellos, h)
	if f.fail {
		return nil, errors.New("validation failed")
	}
	return &tls.Certificate{}, nil
}

func (f *fakeManager) asked() []*tls.ClientHelloInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*tls.ClientHelloInfo(nil), f.hellos...)
}

func phone() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:       "monolith-system.net",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		SupportedCurves:  []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}

// The scanners that found portal on its first deploy each started an order.
func TestVisitorsNeverStartAnOrder(t *testing.T) {
	f := &fakeManager{}
	c := &certs{get: f, domain: "monolith-system.net"}
	for i := 0; i < 20; i++ {
		if _, err := c.GetCertificate(phone()); err != errNoCert {
			t.Fatalf("visitor %d: %v", i, err)
		}
	}
	if n := len(f.asked()); n != 0 {
		t.Fatalf("visitors reached autocert %d times", n)
	}
}

func TestLetsEncryptValidationAlwaysGetsThrough(t *testing.T) {
	f := &fakeManager{}
	c := &certs{get: f, domain: "monolith-system.net"}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "monolith-system.net", SupportedProtos: []string{acme.ALPNProto}}); err != nil {
		t.Fatal(err)
	}
	if len(f.asked()) != 1 {
		t.Fatal("tls-alpn-01 validation was held back")
	}
}

func TestReadyServesOnlyWhatIsCached(t *testing.T) {
	f := &fakeManager{}
	c := &certs{get: f, domain: "monolith-system.net"}
	c.ready.Store(true)
	if _, err := c.GetCertificate(phone()); err != nil {
		t.Fatal(err)
	}
	rsaOnly := &tls.ClientHelloInfo{
		ServerName:       "monolith-system.net",
		SignatureSchemes: []tls.SignatureScheme{tls.PKCS1WithSHA256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	if _, err := c.GetCertificate(rsaOnly); err != errNoCert {
		t.Fatalf("an RSA-only client would start an order of its own: %v", err)
	}
	if len(f.asked()) != 1 {
		t.Fatalf("autocert asked %d times, want 1", len(f.asked()))
	}
}

func TestObtainAsksAsAPhoneAndRetries(t *testing.T) {
	f := &fakeManager{fail: true}
	c := &certs{get: f, domain: "monolith-system.net", first: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.obtain(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for len(f.asked()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(f.asked()) < 2 {
		t.Fatal("a failed attempt was not retried")
	}
	if c.ready.Load() {
		t.Fatal("ready without a certificate")
	}
	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()
	for !c.ready.Load() && time.Now().Before(deadline.Add(2*time.Second)) {
		time.Sleep(5 * time.Millisecond)
	}
	if !c.ready.Load() {
		t.Fatal("never ready")
	}
	for _, h := range f.asked() {
		if h.ServerName != "monolith-system.net" || !ecdsaCapable(h) {
			t.Fatalf("asked as %+v, not as a phone: that would fetch the RSA certificate", h)
		}
	}
}

func TestAcmeProblemsAreRead(t *testing.T) {
	authz := `{"status":"invalid","identifier":{"type":"dns","value":"monolith-system.net"},
	  "challenges":[
	    {"type":"tls-alpn-01","status":"invalid","error":{"type":"urn:ietf:params:acme:error:connection","detail":"93.175.5.49: Timeout during connect (likely firewall problem)"}},
	    {"type":"http-01","status":"pending"}]}`
	got := acmeProblems([]byte(authz))
	if len(got) != 1 || !strings.Contains(got[0], "tls-alpn-01 connection: 93.175.5.49: Timeout during connect") {
		t.Fatalf("read %q", got)
	}
	limited := `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many failed authorizations (5)","status":429}`
	if got := acmeProblems([]byte(limited)); len(got) != 1 || !strings.HasPrefix(got[0], "rateLimited:") {
		t.Fatalf("read %q", got)
	}
	if got := acmeProblems([]byte(`{"status":"valid","challenges":[{"type":"http-01","status":"valid"}]}`)); len(got) != 0 {
		t.Fatalf("a good answer read as a problem: %q", got)
	}
}
