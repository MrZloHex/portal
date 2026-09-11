package portal

import (
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MrZloHex/monolink"
	"github.com/MrZloHex/monolink/marshal"
)

// ─── an in-process concentrator ──────────────────────────────────────

type bus struct {
	url     string
	mu      sync.Mutex
	clients map[*websocket.Conn]bool
	frames  []string
}

func newBus(t *testing.T) *bus {
	t.Helper()
	b := &bus{clients: map[*websocket.Conn]bool{}}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.clients[c] = true
		b.mu.Unlock()
		defer func() {
			b.mu.Lock()
			delete(b.clients, c)
			b.mu.Unlock()
			c.Close()
		}()
		for {
			mt, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.frames = append(b.frames, string(data))
			for o := range b.clients {
				if o != c {
					o.WriteMessage(mt, data)
				}
			}
			b.mu.Unlock()
		}
	}))
	t.Cleanup(srv.Close)
	b.url = "ws" + strings.TrimPrefix(srv.URL, "http")
	return b
}

func (b *bus) relayed() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.frames)
}

func (b *bus) waitFrame(t *testing.T, match func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range b.relayed() {
			if match(f) {
				return f
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no matching frame on the bus; relayed: %q", b.relayed())
	return ""
}

func quiet() []monolink.Option {
	return []monolink.Option{monolink.WithReconnect(0), monolink.WithLogger(stdlog.New(io.Discard, "", 0))}
}

func (b *bus) node(t *testing.T, name string) *monolink.Client {
	t.Helper()
	c := monolink.New(name, b.url, append(quiet(), monolink.WithDialect(monolink.V2))...)
	t.Cleanup(func() { c.Close() })
	return c
}

// ─── a marshal that knows one person, dasha, allowed VERTEX.* ────────

const secret = "pa55word"

func fakeMarshal(t *testing.T, b *bus) {
	t.Helper()
	kdf, err := marshal.NewKDF()
	if err != nil {
		t.Fatal(err)
	}
	verifier := kdf.Verifier(secret)
	var mu sync.Mutex
	nonces := map[string]string{}   // nonce -> panel
	sessions := map[string]string{} // token -> user

	c := b.node(t, marshal.Node)
	c.Handle("*", func(r *monolink.Request) {
		m := r.Msg
		if m.To != marshal.Node || m.Version != monolink.V2 {
			return
		}
		from, _ := monolink.ParseAddress(m.From)
		mu.Lock()
		defer mu.Unlock()
		switch m.Verb + ":" + m.Noun {
		case "AUTH:USER":
			n := busID()
			nonces[n] = from.Node
			r.Reply(monolink.VerbOK, marshal.NounChallenge, kdf.String(), n)
		case "AUTH:PROOF":
			name, n, proof := m.Args[0], m.Args[1], m.Args[2]
			panel, ok := nonces[n]
			delete(nonces, n)
			if !ok || name != "dasha" || !marshal.CheckProof(verifier, name, panel, n, proof) {
				r.Reply(monolink.VerbErr, monolink.CodeDenied)
				return
			}
			tok := "tok" + n
			sessions[tok] = name
			r.Reply(monolink.VerbOK, marshal.NounSession, tok, name, time.Now().Add(time.Hour).Format(time.RFC3339))
		case "SET:SESSION":
			if u, ok := sessions[m.Args[0]]; ok {
				r.Reply(monolink.VerbOK, marshal.NounSession, m.Args[0], u, time.Now().Add(time.Hour).Format(time.RFC3339))
			} else {
				r.Reply(monolink.VerbErr, monolink.CodeNAC)
			}
		case "STOP:SESSION":
			delete(sessions, m.Args[0])
			r.Reply(monolink.VerbOK, marshal.NounSession, m.Args[0], "dasha", time.Now().Format(time.RFC3339))
		case "GET:GRANTS":
			if from.Actor == "dasha" && len(sessions) > 0 {
				r.Reply(monolink.VerbOK, marshal.NounGrants, "VERTEX.*")
			} else {
				r.Reply(monolink.VerbErr, monolink.CodeDenied, "sign in first")
			}
		}
	})
	if err := c.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// fakeVertex is a node with one writable property, as the bridge presents vertex.
func fakeVertex(t *testing.T, b *bus) *monolink.Property {
	t.Helper()
	c := b.node(t, "VERTEX")
	n := monolink.NewNode(c, monolink.NodeInfo{Class: monolink.ClassLeaf, Product: "vertex", Version: "test"})
	lamp := n.WritableProp("LAMP.STATE", monolink.Bool(), "the lamp", nil)
	if err := c.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	return lamp
}

// ─── a browser ───────────────────────────────────────────────────────

type browser struct {
	t  *testing.T
	ws *websocket.Conn
	in chan string
}

func openPortal(t *testing.T, b *bus) string {
	t.Helper()
	p := New(Options{HubURL: b.url, Dial: []monolink.Option{monolink.WithLogger(stdlog.New(io.Discard, "", 0))}})
	srv := httptest.NewServer(http.HandlerFunc(p.ServeBus))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func connect(t *testing.T, portalURL string) *browser {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial(portalURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	br := &browser{t: t, ws: ws, in: make(chan string, 64)}
	go func() {
		defer close(br.in)
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			br.in <- string(data)
		}
	}()
	t.Cleanup(func() { ws.Close() })
	time.Sleep(50 * time.Millisecond) // its bus connection comes up
	return br
}

func (br *browser) send(frame string) {
	br.t.Helper()
	if err := br.ws.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
		br.t.Fatal(err)
	}
}

// expect waits for the next frame the browser is given that matches.
func (br *browser) expect(match func(monolink.Message) bool) monolink.Message {
	br.t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case f, ok := <-br.in:
			if !ok {
				br.t.Fatal("portal closed the socket")
			}
			m, err := monolink.Parse(f)
			if err == nil && match(m) {
				return m
			}
		case <-timeout:
			br.t.Fatal("the browser was not given the frame it waited for")
		}
	}
}

// quiet reports whether the browser is given nothing matching for a while.
func (br *browser) nothing(match func(string) bool) bool {
	timeout := time.After(300 * time.Millisecond)
	for {
		select {
		case f, ok := <-br.in:
			if ok && match(f) {
				return false
			}
		case <-timeout:
			return true
		}
	}
}

func id(want string) func(monolink.Message) bool {
	return func(m monolink.Message) bool { return m.ID == want }
}

// signIn goes through the challenge exactly as the app will.
func (br *browser) signIn(name, secret string) monolink.Message {
	br.t.Helper()
	br.send("2:c1:X:MARSHAL:AUTH:USER:" + name)
	ch := br.expect(id("c1"))
	if ch.Noun != marshal.NounChallenge {
		br.t.Fatalf("challenge: %+v", ch)
	}
	kdf, err := marshal.ParseKDF(ch.Args[0])
	if err != nil {
		br.t.Fatal(err)
	}
	proof := marshal.Proof(kdf.Verifier(secret), name, Panel, ch.Args[1])
	br.send("2:c2:X:MARSHAL:AUTH:PROOF:" + name + ":" + ch.Args[1] + ":" + proof)
	return br.expect(id("c2"))
}

// ─── tests ───────────────────────────────────────────────────────────

func TestAnonymousMayOnlySignIn(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	br := connect(t, openPortal(t, b))

	br.send("2:a1:X:VERTEX:SET:LAMP.STATE:ON")
	if m := br.expect(id("a1")); m.Verb != monolink.VerbErr || m.Noun != monolink.CodeDenied {
		t.Fatalf("anonymous SET answered %+v", m)
	}
	br.send("2:a2:X:MARSHAL:AUTH:ENROL:CODE:eve:k:v")
	if m := br.expect(id("a2")); m.Noun != monolink.CodeDenied {
		t.Fatalf("enrolment through portal answered %+v", m)
	}
	for _, f := range b.relayed() {
		if strings.Contains(f, ":SET:LAMP.STATE") || strings.Contains(f, ":AUTH:ENROL") {
			t.Fatalf("reached the bus: %q", f)
		}
	}
}

func TestSignInThenGrantsDecide(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	br := connect(t, openPortal(t, b))

	if s := br.signIn("dasha", secret); s.Noun != marshal.NounSession || s.Args[1] != "dasha" {
		t.Fatalf("sign in answered %+v", s)
	}
	br.send("2:s1:X:VERTEX:SET:LAMP.STATE:ON")
	if m := br.expect(id("s1")); m.Verb != monolink.VerbOK || m.Arg(0) != "ON" {
		t.Fatalf("SET within a grant answered %+v", m)
	}
	b.waitFrame(t, func(f string) bool { return strings.Contains(f, ":MONOWEB.dasha:VERTEX:SET:LAMP.STATE:ON") })

	br.send("2:s2:X:UKAZ:DO:PRINT.AGENDA")
	if m := br.expect(id("s2")); m.Noun != monolink.CodeDenied || !strings.Contains(m.Arg(0), "UKAZ.DO.PRINT.AGENDA") {
		t.Fatalf("DO outside every grant answered %+v", m)
	}
}

func TestWrongSecretSignsNobodyIn(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	br := connect(t, openPortal(t, b))
	if m := br.signIn("dasha", "wrong"); m.Verb != monolink.VerbErr {
		t.Fatalf("wrong secret answered %+v", m)
	}
	br.send("2:w1:X:VERTEX:SET:LAMP.STATE:ON")
	if m := br.expect(id("w1")); m.Noun != monolink.CodeDenied {
		t.Fatalf("after a wrong secret, SET answered %+v", m)
	}
}

// Whatever sender a browser writes, the bus sees the one portal gives it.
func TestBrowserCannotChooseWhoItIs(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	br := connect(t, openPortal(t, b))
	br.signIn("dasha", secret)
	br.send("2:f1:MONOVIEW.mzh:VERTEX:SET:LAMP.STATE:OFF")
	br.expect(id("f1"))
	for _, f := range b.relayed() {
		if strings.Contains(f, "MONOVIEW.mzh") {
			t.Fatalf("a browser spoke as someone else: %q", f)
		}
	}
	b.waitFrame(t, func(f string) bool { return strings.Contains(f, ":MONOWEB.dasha:VERTEX:SET:LAMP.STATE:OFF") })
}

// Two browsers asking with the same id: each hears only its own answer —
// above all, no one else's session token.
func TestAnswersGoOnlyToWhoAsked(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	url := openPortal(t, b)
	a, other := connect(t, url), connect(t, url)
	other.send("2:c2:X:MARSHAL:AUTH:USER:ghost") // the same id a is about to use
	a.signIn("dasha", secret)
	if !other.nothing(func(f string) bool { return strings.Contains(f, ":SESSION:") }) {
		t.Fatal("another browser was given the session")
	}
}

func TestAnnouncementsFollowGrants(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	lamp := fakeVertex(t, b)
	br := connect(t, openPortal(t, b))

	lamp.Set("ON")
	if !br.nothing(func(f string) bool { return strings.Contains(f, ":PUB:") }) {
		t.Fatal("an anonymous browser heard an announcement")
	}

	br.signIn("dasha", secret)
	lamp.Set("OFF")
	br.expect(func(m monolink.Message) bool {
		return m.Verb == monolink.VerbPub && m.Noun == "LAMP.STATE" && m.Arg(0) == "OFF"
	})

	gov := b.node(t, "GOVERNOR")
	if err := gov.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	gov.SendRaw("2:g1:GOVERNOR:ALL:PUB:NEXT.DEADLINE:2026-09-12T10%3A00%3A00+03%3A00")
	if !br.nothing(func(f string) bool { return strings.Contains(f, "NEXT.DEADLINE") }) {
		t.Fatal("dasha heard a value no grant lets her read")
	}
}

func TestSignOutTakesTheNameOff(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	br := connect(t, openPortal(t, b))
	s := br.signIn("dasha", secret)
	br.send("2:o1:X:MARSHAL:STOP:SESSION:" + s.Args[0])
	br.expect(id("o1"))
	br.send("2:o2:X:VERTEX:SET:LAMP.STATE:ON")
	if m := br.expect(id("o2")); m.Noun != monolink.CodeDenied {
		t.Fatalf("after signing out, SET answered %+v", m)
	}
}

func TestCrossSitePagesAreRefused(t *testing.T) {
	b := newBus(t)
	url := openPortal(t, b)
	_, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Origin": {"https://evil.example"}})
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a page on another site opened a socket: %v", err)
	}
}
