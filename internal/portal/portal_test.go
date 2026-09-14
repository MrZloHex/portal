package portal

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
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

// dashasPhone is the one passkey the fake marshal knows. It checks nothing
// else of an assertion: that is marshal's to do, and marshal's tests'.
const dashasPhone = "dashas-phone"

// invitation is the one code it takes up, for anybody.
const invitation = "GOOD-CODE"

var _, ticketKey, _ = ed25519.GenerateKey(rand.Reader)

func fakeMarshal(t *testing.T, b *bus) {
	t.Helper()
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
		case "AUTH:CHALLENGE":
			n := busID()
			nonces[n] = from.Node
			r.Reply(monolink.VerbOK, marshal.NounChallenge, n)
		case "AUTH:PASSKEY":
			n, cred := m.Args[0], m.Args[1]
			panel, ok := nonces[n]
			delete(nonces, n)
			if !ok || panel != from.Node || cred != dashasPhone {
				r.Reply(monolink.VerbErr, monolink.CodeDenied)
				return
			}
			tok := "tok" + n
			sessions[tok] = "dasha"
			r.Reply(monolink.VerbOK, marshal.NounSession, tok, "dasha", time.Now().Add(time.Hour).Format(time.RFC3339))
		case "AUTH:REDEEM":
			if m.Args[0] != invitation {
				r.Reply(monolink.VerbErr, monolink.CodeDenied)
				return
			}
			tok := "tok" + busID()
			sessions[tok] = m.Args[1]
			r.Reply(monolink.VerbOK, marshal.NounSession, tok, m.Args[1], time.Now().Add(time.Hour).Format(time.RFC3339))
		case "SET:SESSION":
			if u, ok := sessions[m.Args[0]]; ok {
				r.Reply(monolink.VerbOK, marshal.NounSession, m.Args[0], u, time.Now().Add(time.Hour).Format(time.RFC3339))
			} else {
				r.Reply(monolink.VerbErr, monolink.CodeNAC)
			}
		case "STOP:SESSION":
			delete(sessions, m.Args[0])
			r.Reply(monolink.VerbOK, marshal.NounSession, m.Args[0], "dasha", time.Now().Format(time.RFC3339))
		case "GET:TICKET":
			if u, ok := sessions[m.Args[0]]; ok {
				tk := marshal.Ticket{Person: u, Panel: from.Node, Expires: time.Now().Add(marshal.TicketTTL),
					Grants: []string{"VERTEX.*"}}.Sign(ticketKey)
				r.Reply(monolink.VerbOK, marshal.NounTicket, tk.Args()...)
			} else {
				r.Reply(monolink.VerbErr, monolink.CodeNAC)
			}
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

	// and the hub's part in signing in: it takes the ticket
	h := b.node(t, marshal.Hub)
	h.Handle("*", func(r *monolink.Request) {
		m := r.Msg
		if m.To != marshal.Hub || m.Version != monolink.V2 {
			return
		}
		switch m.Verb + ":" + m.Noun {
		case "SET:TICKET":
			if _, err := marshal.ParseTicket(m.Args); err != nil {
				r.Reply(monolink.VerbErr, monolink.CodeArg)
				return
			}
			r.Reply(monolink.VerbOK, marshal.NounTicket)
		case "STOP:TICKET":
			r.Reply(monolink.VerbOK, marshal.NounTicket)
		}
	})
	if err := h.Connect(t.Context()); err != nil {
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

// signIn goes through the challenge as the app will, answering it with the
// passkey cred.
func (br *browser) signIn(cred string) monolink.Message {
	br.t.Helper()
	br.send("2:c1:X:MARSHAL:AUTH:CHALLENGE")
	ch := br.expect(id("c1"))
	if ch.Noun != marshal.NounChallenge {
		br.t.Fatalf("challenge: %+v", ch)
	}
	br.send("2:c2:X:MARSHAL:AUTH:PASSKEY:" + ch.Args[0] + ":" + cred + ":AUTHDATA:SIGNATURE:CLIENTDATA")
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
	br.send("2:a2:X:MARSHAL:AUTH:ENROL:CODE:eve:ed25519:id:-8:key")
	if m := br.expect(id("a2")); m.Noun != monolink.CodeDenied {
		t.Fatalf("enrolment through portal answered %+v", m)
	}
	br.send("2:a3:X:MARSHAL:AUTH:KEY:nonce:mzh:id:sig")
	if m := br.expect(id("a3")); m.Noun != monolink.CodeDenied {
		t.Fatalf("a panel's key through portal answered %+v", m)
	}
	br.send("2:a4:X:MARSHAL:GET:USERS")
	if m := br.expect(id("a4")); m.Noun != monolink.CodeDenied {
		t.Fatalf("an anonymous GET:USERS answered %+v", m)
	}
	for _, f := range b.relayed() {
		if strings.Contains(f, ":SET:LAMP.STATE") || strings.Contains(f, ":AUTH:ENROL") ||
			strings.Contains(f, ":AUTH:KEY") || strings.Contains(f, ":GET:USERS") {
			t.Fatalf("reached the bus: %q", f)
		}
	}
}

func TestSignInThenGrantsDecide(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	br := connect(t, openPortal(t, b))

	if s := br.signIn(dashasPhone); s.Noun != marshal.NounSession || s.Args[1] != "dasha" {
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

func TestAStrangersPasskeySignsNobodyIn(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	br := connect(t, openPortal(t, b))
	if m := br.signIn("a-strangers-passkey"); m.Verb != monolink.VerbErr {
		t.Fatalf("a stranger's passkey answered %+v", m)
	}
	br.send("2:w1:X:VERTEX:SET:LAMP.STATE:ON")
	if m := br.expect(id("w1")); m.Noun != monolink.CodeDenied {
		t.Fatalf("after a refused passkey, SET answered %+v", m)
	}
}

// Taking up an invitation signs the new person in, as signing in does.
func TestAnInvitationSignsIn(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	br := connect(t, openPortal(t, b))
	br.send("2:r1:X:MARSHAL:AUTH:REDEEM:WRONG-CODE:olga:webauthn:id:-7:key")
	if m := br.expect(id("r1")); m.Verb != monolink.VerbErr {
		t.Fatalf("a wrong code answered %+v", m)
	}
	br.send("2:r2:X:MARSHAL:AUTH:REDEEM:" + invitation + ":olga:webauthn:id:-7:key")
	if m := br.expect(id("r2")); m.Noun != marshal.NounSession || m.Arg(1) != "olga" {
		t.Fatalf("the invitation answered %+v", m)
	}
	br.send("2:r3:X:VERTEX:SET:LAMP.STATE:ON")
	br.expect(id("r3"))
	b.waitFrame(t, func(f string) bool { return strings.Contains(f, ":MONOWEB.olga:VERTEX:SET:LAMP.STATE:ON") })
}

// Whatever sender a browser writes, the bus sees the one portal gives it.
func TestBrowserCannotChooseWhoItIs(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	br := connect(t, openPortal(t, b))
	br.signIn(dashasPhone)
	br.send("2:f1:MONOVIEW.mzh:VERTEX:SET:LAMP.STATE:OFF")
	br.expect(id("f1"))
	for _, f := range b.relayed() {
		if strings.Contains(f, "MONOVIEW.mzh") {
			t.Fatalf("a browser spoke as someone else: %q", f)
		}
	}
	b.waitFrame(t, func(f string) bool { return strings.Contains(f, ":MONOWEB.dasha:VERTEX:SET:LAMP.STATE:OFF") })
}

// A node's frames reach the browser in the order it sent them: two PUBs of
// one value arriving swapped would show the lamp on when it is off.
func TestFramesReachTheBrowserInOrder(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	c := b.node(t, "VERTEX")
	n := monolink.NewNode(c, monolink.NodeInfo{Class: monolink.ClassLeaf, Product: "vertex", Version: "test"})
	count := n.Prop("COUNT", monolink.Int(0, 1000), "a counter")
	if err := c.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	br := connect(t, openPortal(t, b))
	br.signIn(dashasPhone)

	const sent = 300
	go func() {
		for i := 1; i <= sent; i++ {
			count.Set(strconv.Itoa(i))
		}
	}()
	for last := 0; last < sent; {
		m := br.expect(func(m monolink.Message) bool { return m.Verb == monolink.VerbPub && m.Noun == "COUNT" })
		v, _ := strconv.Atoi(m.Arg(0))
		if v != last+1 {
			t.Fatalf("after COUNT=%d the browser was given COUNT=%d", last, v)
		}
		last = v
	}
}

// Two browsers asking with the same id: each hears only its own answer —
// above all, no one else's session token.
func TestAnswersGoOnlyToWhoAsked(t *testing.T) {
	b := newBus(t)
	fakeMarshal(t, b)
	fakeVertex(t, b)
	url := openPortal(t, b)
	a, other := connect(t, url), connect(t, url)
	other.send("2:c2:X:MARSHAL:AUTH:CHALLENGE") // the same id a is about to use
	a.signIn(dashasPhone)
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

	br.signIn(dashasPhone)
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
	s := br.signIn(dashasPhone)
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
