package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	log "log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
)

// getter is what portal needs of autocert.Manager.
type getter interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// certs keeps the public certificate on portal's own schedule.
//
// autocert orders a certificate on the first handshake that needs one — and
// the internet's scanners find a new HTTPS site within minutes and handshake
// with it constantly. On the first deploy, with Let's Encrypt's validation
// failing, every scanner's handshake started an order, and the five failed
// validations Let's Encrypt allows a name in an hour went in ten minutes. So
// portal asks at startup, and again after a growing delay if that fails;
// nobody's handshake starts an order.
type certs struct {
	get    getter
	domain string
	ready  atomic.Bool
	first  time.Duration // delay before the second attempt; doubles, up to two hours
}

var errNoCert = errors.New("portal: no certificate yet")

func (c *certs) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Let's Encrypt's own tls-alpn-01 validation must always get through.
	if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto {
		return c.get.GetCertificate(hello)
	}
	// Nothing to give until the certificate is here — and nothing to a client
	// that could only take an RSA one, which would start an order of its own.
	if !c.ready.Load() || !ecdsaCapable(hello) {
		return nil, errNoCert
	}
	return c.get.GetCertificate(hello)
}

// obtain gets the certificate, or returns at once if it is cached, and
// retries with a growing delay until it has one.
func (c *certs) obtain(ctx context.Context) {
	// Asked as a phone asks, so the certificate obtained is the ECDSA one
	// phones will want.
	hello := &tls.ClientHelloInfo{
		ServerName:       c.domain,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	wait := c.first
	if wait <= 0 {
		wait = 10 * time.Minute
	}
	for {
		_, err := c.get.GetCertificate(hello)
		if err == nil {
			c.ready.Store(true)
			log.Info("CERTIFICATE READY", "domain", c.domain)
			return
		}
		log.Warn("no certificate yet", "domain", c.domain, "next try in", wait, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, 2*time.Hour)
	}
}

// ecdsaCapable is autocert's own test (supportsECDSA): the client could use
// the ECDSA certificate rather than needing an RSA one.
func ecdsaCapable(hello *tls.ClientHelloInfo) bool {
	if hello.SignatureSchemes != nil {
		ok := false
		for _, s := range hello.SignatureSchemes {
			switch s {
			case 0x0203, tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512:
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if hello.SupportedCurves != nil {
		ok := false
		for _, c := range hello.SupportedCurves {
			if c == tls.CurveP256 {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	for _, s := range hello.CipherSuites {
		switch s {
		case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
			return true
		}
	}
	return false
}

// problems logs what Let's Encrypt says went wrong. autocert keeps only
// "no viable challenge type found"; the reasons — "Timeout during connect
// (likely firewall problem)" and the like — are in the ACME responses it
// reads and throws away.
type problems struct{ next http.RoundTripper }

func (p problems) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := p.next.RoundTrip(r)
	if err != nil || res.Body == nil {
		return res, err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	for _, why := range acmeProblems(body) {
		log.Warn("Let's Encrypt says", "problem", why)
	}
	return res, nil
}

type acmeProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// acmeProblems finds the problem documents in an ACME response: the
// response itself, an object's error, and each challenge's error.
func acmeProblems(body []byte) []string {
	var v struct {
		acmeProblem
		Error      *acmeProblem `json:"error"`
		Challenges []struct {
			Type  string       `json:"type"`
			Error *acmeProblem `json:"error"`
		} `json:"challenges"`
	}
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	const urn = "urn:ietf:params:acme:error:"
	var out []string
	if strings.HasPrefix(v.Type, urn) {
		out = append(out, strings.TrimPrefix(v.Type, urn)+": "+v.Detail)
	}
	if v.Error != nil {
		out = append(out, strings.TrimPrefix(v.Error.Type, urn)+": "+v.Error.Detail)
	}
	for _, c := range v.Challenges {
		if c.Error != nil {
			out = append(out, c.Type+" "+strings.TrimPrefix(c.Error.Type, urn)+": "+c.Error.Detail)
		}
	}
	return out
}
