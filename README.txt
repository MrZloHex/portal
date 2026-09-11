
  ░▒▓█ _portal_ █▓▒░
  The bubble's one door to the internet. SPEC.txt §23.


  ───────────────────────────────────────────────────────────────
  ▓ WHAT IT IS

  One Go binary on the laptop, and the only thing the router forwards to.
  It serves the app (monoweb) over ordinary HTTPS with a certificate from
  Let's Encrypt, and gives each browser a bus connection of its own, as
  MONOWEB. The concentrator stays on the LAN.

  A phone holds no bubble certificate, so portal does not trust it the way
  the bubble trusts its own nodes:

  ▪ Portal writes the sender: MONOWEB until someone signs in,
    MONOWEB.<person> after. A browser cannot say it is anyone else.
  ▪ Until then only marshal's sign-in passes — AUTH:USER, AUTH:PROOF,
    SET:SESSION. The first person enrols at home, never over the internet.
  ▪ After, everything is checked against the person's grants, and enforced
    here rather than advised.
  ▪ A browser hears the answers to its own requests and the announcements
    of what its person may read. Nothing else.
  ▪ Every request it forwards gets a random id of portal's, so two
    browsers can never be given each other's answers — a session token
    above all.
  ▪ A page on another site cannot open a socket here, and every response
    carries CSP, HSTS and no-framing headers.


  ───────────────────────────────────────────────────────────────
  ▓ THE WIRE

    wss://<domain>/bus      one monolink v2 frame per message

  Exactly as on the bus. A browser signs in with the same challenge as any
  panel (marshal's README), proving its secret for the panel MONOWEB. Its
  own ids come back on the answers; the sender it writes is ignored.


  ───────────────────────────────────────────────────────────────
  ▓ BUILD & RUN

    go build -o bin/portal ./cmd/portal
    go test ./...

  On the LAN, in plain HTTP, to try it:

    ./bin/portal --insecure            # http://192.168.0.69:8080

  The app is built into the binary from web/dist/. monoweb's build writes
  it there; --web <dir> serves a directory instead, for working on the app.


  ───────────────────────────────────────────────────────────────
  ▓ CONFIGURATION

  Flags, with .env in the working directory supplying defaults:

        --domain        PORTAL_DOMAIN        the public name, e.g. home.example.org
        --listen        PORTAL_LISTEN        :443  (:8080 with --insecure)
        --insecure      PORTAL_INSECURE      plain HTTP, LAN testing only
        --acme-cache    PORTAL_ACME_CACHE    acme/  (account and certificates)
        --email         PORTAL_EMAIL         contact for Let's Encrypt, optional
        --acme-staging  PORTAL_ACME_STAGING  Let's Encrypt's test service, see below
        --web           PORTAL_WEB           serve the app from a directory
    -u, --url           PORTAL_HUB_URL       wss://127.0.0.1:8443
        --tls-cert      PORTAL_TLS_CERT      the bus certificate
        --tls-key       PORTAL_TLS_KEY
        --tls-ca        PORTAL_TLS_CA
        --max-sessions                       32
    -l, --log           PORTAL_LOG           info

  On the server:

    PORTAL_DOMAIN=home.example.org
    PORTAL_HUB_URL=wss://127.0.0.1:8443
    PORTAL_TLS_CERT=../pki/portal/portal.cert.pem
    PORTAL_TLS_KEY=../pki/portal/portal.key.pem
    PORTAL_TLS_CA=../pki/intermediate/certs/ca-chain.cert.pem


  ───────────────────────────────────────────────────────────────
  ▓ DEPLOY

  1. A bus certificate:   cd ~/Projects/monolith/pki && bash issue.sh portal
  2. .env as above, then  go build -o bin/portal ./cmd/portal
  3. The router forwards TCP 443 and 80 to 192.168.0.69. 80 serves only
     Let's Encrypt's renewals and a redirect to https.
  4. DNS at deSEC, kept on the dynamic IP by deploy/desec-ddns.*:

       sudo install -m 600 /dev/null /etc/desec-ddns.env
       # DESEC_DOMAIN=example.org  DESEC_HOST=home.example.org  DESEC_TOKEN=…
       sudo cp deploy/desec-ddns.service deploy/desec-ddns.timer /etc/systemd/system/
       sudo systemctl enable --now desec-ddns.timer

  5. portal itself. The unit lets it bind 443 and 80 without root:

       sudo cp deploy/portal.service /etc/systemd/system/
       sudo systemctl daemon-reload && sudo systemctl enable --now portal

  ─── The certificate ───
  portal asks Let's Encrypt for it at startup, and retries after 10 min,
  20, … up to two hours apart until it has one; then it renews itself. A
  visitor never starts an order: the internet's scanners find a new HTTPS
  site within minutes, and Let's Encrypt allows a name five failed
  validations an hour. Each failed check is logged with Let's Encrypt's own
  reason ("Let's Encrypt says …").

  To prove the setup without spending that allowance, run once with
  PORTAL_ACME_STAGING=1: the test service has generous limits and issues a
  certificate no browser trusts, kept apart in acme-staging/. When the log
  says CERTIFICATE READY, remove the line and restart.
