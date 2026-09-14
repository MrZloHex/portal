
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
  ▪ Until then only marshal's sign-in passes — AUTH:CHALLENGE,
    AUTH:PASSKEY, AUTH:REDEEM, SET:SESSION. The first person enrols at
    home, never over the internet, and a browser signs in with a passkey
    only: never AUTH:ENROL, never a panel's AUTH:KEY.
  ▪ After, everything is checked against the person's grants, and enforced
    here rather than advised — and again at the hub: portal shows it the
    ticket marshal signs for the session, renews it every four minutes,
    and takes it off when the person signs out (SECURITY.txt §5).
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

  Exactly as on the bus. A browser signs in with a passkey, answering
  marshal's challenge to the panel MONOWEB (marshal's README). Its own ids
  come back on the answers; the sender it writes is ignored.


  ───────────────────────────────────────────────────────────────
  ▓ BUILD & RUN

    go build -o bin/portal ./cmd/portal
    go test ./...

  In plain HTTP, to try it — on this machine alone unless told otherwise:

    ./bin/portal --insecure                                  # http://127.0.0.1:8080
    ./bin/portal --insecure --listen 192.168.0.42:8080       # the LAN too

  The app is built into the binary from web/dist/. monoweb's build writes
  it there; --web <dir> serves a directory instead, for working on the app.


  ───────────────────────────────────────────────────────────────
  ▓ CONFIGURATION

  Flags, with .env in the working directory supplying defaults:

        --domain        PORTAL_DOMAIN        the public name, e.g. home.example.org
        --listen        PORTAL_LISTEN        :443  (127.0.0.1:8080 with --insecure)
        --insecure      PORTAL_INSECURE      plain HTTP, testing only (true/false)
        --acme-cache    PORTAL_ACME_CACHE    acme/  (account and certificates)
        --email         PORTAL_EMAIL         contact for Let's Encrypt, optional
        --acme-staging  PORTAL_ACME_STAGING  Let's Encrypt's test service, see below
        --web           PORTAL_WEB           serve the app from a directory
    -u, --url           PORTAL_HUB_URL       wss://127.0.0.1:8443
        --tls-cert      PORTAL_TLS_CERT      the bus certificate
        --tls-key       PORTAL_TLS_KEY
        --tls-ca        PORTAL_TLS_CA        the bubble CA
        --max-sessions                       32
    -l, --log           PORTAL_LOG           info

  It does not start without all three bus TLS files and a wss:// hub URL.

  ─── Strangers ───
  A browser nobody signs in on is closed after two minutes; the app
  reconnects by itself. From one internet address: eight sockets at once,
  ten sign-in challenges and then ten a minute, five tries at an
  invitation and then one every three minutes. The home network, the
  tunnel and the machine itself are not rationed — a router looping the
  household's phones back in shows them all as one address.


  ───────────────────────────────────────────────────────────────
  ▓ DEPLOY

  Through deploy/'s monolithctl, with MONOLITH's release: its own user, a
  sandboxed unit that may bind 443 and 80 and nothing more, its key sealed
  (deploy/README.txt). The router forwards TCP 443 and 80 to the server;
  80 serves only Let's Encrypt's renewals and a redirect to https. The
  name stays on the dynamic IP by monolithctl's DDNS, with a deSEC token
  restricted to that one record (deploy/README.txt).

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
