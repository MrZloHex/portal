package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
	log "log/slog"

	cli "github.com/spf13/pflag"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/MrZloHex/monolink"
	"portal/internal/portal"
	"portal/web"
)

var logLevelMap = map[string]log.Level{
	"debug": log.LevelDebug,
	"info":  log.LevelInfo,
	"warn":  log.LevelWarn,
	"error": log.LevelError,
}

func loadDotEnv() {
	err := godotenv.Load()
	var pe *os.PathError
	if err == nil || errors.Is(err, os.ErrNotExist) || (errors.As(err, &pe) && errors.Is(pe.Err, os.ErrNotExist)) {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "portal: warning: .env: %v\n", err)
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// envBool is a yes-or-no variable; unset, empty or unreadable is no. Once any
// value at all meant yes, and PORTAL_INSECURE=false turned plain HTTP on.
func envBool(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "portal: warning: %s=%q is neither yes nor no; taken as no\n", key, v)
		return false
	}
	return b
}

func main() {
	loadDotEnv()

	domain := cli.String("domain", env("PORTAL_DOMAIN", ""), "Public name portal answers to; its certificate comes from Let's Encrypt (env PORTAL_DOMAIN)")
	listen := cli.String("listen", env("PORTAL_LISTEN", ""), "Address to serve on; default :443, or 127.0.0.1:8080 with --insecure (env PORTAL_LISTEN)")
	insecure := cli.Bool("insecure", envBool("PORTAL_INSECURE"), "Plain HTTP, for testing only (env PORTAL_INSECURE)")
	acmeCache := cli.String("acme-cache", env("PORTAL_ACME_CACHE", "acme"), "Where the Let's Encrypt account and certificates are kept (env PORTAL_ACME_CACHE)")
	email := cli.String("email", env("PORTAL_EMAIL", ""), "Contact for Let's Encrypt, optional (env PORTAL_EMAIL)")
	acmeStaging := cli.Bool("acme-staging", envBool("PORTAL_ACME_STAGING"), "Use Let's Encrypt's test service: generous limits, a certificate no browser trusts — for proving the setup (env PORTAL_ACME_STAGING)")
	webDir := cli.String("web", env("PORTAL_WEB", ""), "Serve the app from this directory instead of the built-in copy (env PORTAL_WEB)")
	maxSessions := cli.Int("max-sessions", 32, "Browsers connected at once")
	hubURL := cli.StringP("url", "u", env("PORTAL_HUB_URL", "wss://127.0.0.1:8443"), "Hub URL (env PORTAL_HUB_URL)")
	tlsCert := cli.String("tls-cert", os.Getenv("PORTAL_TLS_CERT"), "Client certificate PEM for the bus (env PORTAL_TLS_CERT)")
	tlsKey := cli.String("tls-key", os.Getenv("PORTAL_TLS_KEY"), "Client private key PEM for the bus (env PORTAL_TLS_KEY)")
	tlsCA := cli.String("tls-ca", os.Getenv("PORTAL_TLS_CA"), "The bubble CA's PEM, which vouches for the hub (env PORTAL_TLS_CA)")
	logLevel := cli.StringP("log", "l", env("PORTAL_LOG", "info"), "Log level (env PORTAL_LOG)")
	cli.Parse()

	handler := tint.NewHandler(os.Stdout, &tint.Options{Level: logLevelMap[*logLevel]})
	log.SetDefault(log.New(handler))

	if !*insecure && *domain == "" {
		log.Error("--domain is required, or --insecure to test on the LAN")
		os.Exit(2)
	}
	if *listen == "" {
		*listen = ":443"
		if *insecure {
			*listen = "127.0.0.1:8080" // a LAN address, or any, only when given
		}
	}

	busTLS, err := monolink.SecureTLS(*hubURL, *tlsCert, *tlsKey, *tlsCA)
	if err != nil {
		log.Error("cannot reach the hub safely", "err", err)
		os.Exit(1)
	}
	dial := []monolink.Option{monolink.WithLogger(log.NewLogLogger(handler, log.LevelWarn)), monolink.WithTLS(busTLS)}

	mime.AddExtensionType(".webmanifest", "application/manifest+json")
	app, err := fs.Sub(web.FS, "dist")
	if err != nil {
		log.Error("built-in app missing", "err", err)
		os.Exit(1)
	}
	if *webDir != "" {
		// A root, not a plain directory: a symlink in it leads nowhere
		// outside it.
		root, err := os.OpenRoot(*webDir)
		if err != nil {
			log.Error("--web", "err", err)
			os.Exit(1)
		}
		app = root.FS()
	}

	p := portal.New(portal.Options{HubURL: *hubURL, Dial: dial, MaxSessions: *maxSessions})
	mux := http.NewServeMux()
	mux.HandleFunc("/bus", p.ServeBus)
	mux.Handle("/", files(app))
	site := headers(mux, !*insecure)

	// The timeouts are for files and for idle connections; /bus sets its own
	// deadlines on every read and write once upgraded.
	srv := &http.Server{Addr: *listen, Handler: site, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()

	if *insecure {
		log.Warn("PLAIN HTTP — for testing on the LAN only", "listen", *listen, "hub", *hubURL)
		err = srv.ListenAndServe()
	} else {
		directory, cache := autocert.DefaultACMEDirectory, *acmeCache
		if *acmeStaging {
			directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
			cache += "-staging" // a test certificate must never be served as the real one
			log.Warn("TEST CERTIFICATES from Let's Encrypt staging: no browser will trust them")
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(cache),
			Email:      *email,
			Client: &acme.Client{
				DirectoryURL: directory,
				HTTPClient:   &http.Client{Transport: problems{http.DefaultTransport}, Timeout: time.Minute},
			},
		}
		c := &certs{get: m, domain: *domain}
		srv.TLSConfig = m.TLSConfig()
		srv.TLSConfig.GetCertificate = c.GetCertificate
		go c.obtain(ctx)
		// Port 80 answers Let's Encrypt's challenges and sends everyone else
		// to https. The certificate itself is obtained on 443 as well.
		go func() {
			redirect := &http.Server{Addr: ":80", Handler: m.HTTPHandler(nil), ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute}
			if err := redirect.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warn("port 80 unavailable; certificates come through 443 alone", "err", err)
			}
		}()
		log.Info("BOOTING UP", "domain", *domain, "listen", *listen, "hub", *hubURL)
		err = srv.ListenAndServeTLS("", "")
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve failed", "err", err)
		os.Exit(1)
	}
	log.Info("SHUTTING DOWN")
}

// files serves the app, and nothing that is not one of its files: no
// directory listings, nothing whose name starts with a dot.
func files(app fs.FS) http.Handler {
	serve := http.FileServerFS(app)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if (strings.HasSuffix(p, "/") && p != "/") || strings.Contains(p, "/.") {
			http.NotFound(w, r)
			return
		}
		serve.ServeHTTP(w, r)
	})
}

// headers adds what every response from a door to the internet should
// carry: nothing framed, nothing sniffed, no referrer, scripts and sockets
// from here only — and, over TLS, HSTS. The app compiles no WebAssembly:
// it signs in with a passkey, which the browser holds, so script-src needs
// no 'wasm-unsafe-eval' and does not have it.
func headers(next http.Handler, tls bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), hid=()")
		if tls {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasSuffix(r.URL.Path, "/sw.js") {
			h.Set("Cache-Control", "no-cache") // an app update reaches phones on their next visit
		}
		next.ServeHTTP(w, r)
	})
}
