// Package portal is the bubble's one door to the internet: ordinary TLS and
// marshal sign-in outside, mTLS on the bus inside.
//
// A browser speaks monolink v2 to portal over a WebSocket, as any panel
// speaks it to the concentrator. But a phone holds no bubble certificate,
// so portal does not trust it the way the bubble trusts its own nodes:
//
//   - Each browser gets a bus connection of its own, as MONOWEB, and portal
//     writes the sender: MONOWEB until someone signs in, MONOWEB.<person>
//     after. A browser cannot say it is anyone else.
//   - Until then it may only sign in. After, everything it sends is checked
//     against the person's grants, here — enforced, not advised (SPEC §24),
//     because the internet is not the household.
//   - It hears only the answers to its own requests, and the announcements
//     of what its person may read. Nobody else's traffic.
package portal

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MrZloHex/monolink"
	"github.com/MrZloHex/monolink/marshal"
)

// Panel is the node every browser speaks as. A browser signing in proves
// its secret for this panel: marshal.Proof(verifier, name, Panel, nonce).
const Panel = "MONOWEB"

const (
	pingEvery    = 30 * time.Second
	readTimeout  = 2 * pingEvery
	writeTimeout = 5 * time.Second
	pendingTTL   = time.Minute     // an unanswered request is forgotten after this
	grantsEvery  = 5 * time.Minute // how often a signed-in session re-reads its grants
	askTimeout   = 5 * time.Second
	rateBurst    = 40 // frames a browser may send at once
	ratePerSec   = 20 // and then per second
)

// Options configures a Portal.
type Options struct {
	HubURL      string
	Dial        []monolink.Option // for every session's bus connection: TLS, logger
	MaxSessions int
}

// Portal serves browsers' bus connections.
type Portal struct {
	opt Options
	up  websocket.Upgrader

	mu       sync.Mutex
	sessions int
}

func New(opt Options) *Portal {
	if opt.MaxSessions <= 0 {
		opt.MaxSessions = 32
	}
	p := &Portal{opt: opt}
	p.up = websocket.Upgrader{CheckOrigin: sameOrigin}
	return p
}

// sameOrigin refuses a page on another site opening a socket here with the
// visitor's browser. A request with no Origin is not from a browser.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

// ServeBus turns a browser's request into a session on the bus.
func (p *Portal) ServeBus(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	full := p.sessions >= p.opt.MaxSessions
	if !full {
		p.sessions++
	}
	p.mu.Unlock()
	if full {
		http.Error(w, "too many sessions", http.StatusServiceUnavailable)
		return
	}
	defer func() {
		p.mu.Lock()
		p.sessions--
		p.mu.Unlock()
	}()

	ws, err := p.up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s := &session{p: p, ws: ws, pending: map[string]pending{}, tokens: rateBurst, filled: time.Now()}
	s.run(r.Context())
}

// ─── one browser ─────────────────────────────────────────────────────

type pending struct {
	browserID  string
	verb, noun string
	at         time.Time
}

type session struct {
	p   *Portal
	ws  *websocket.Conn
	wmu sync.Mutex
	bus *monolink.Client

	mu      sync.Mutex
	user    string
	grants  []string
	pending map[string]pending // by the id portal gave the request on the bus
	tokens  float64
	filled  time.Time
}

func (s *session) run(ctx context.Context) {
	defer s.ws.Close()
	s.bus = monolink.New(Panel, s.p.opt.HubURL,
		append([]monolink.Option{monolink.WithDialect(monolink.V2), monolink.WithReconnect(0)}, s.p.opt.Dial...)...)
	s.bus.Handle("*", s.fromBus)
	if err := s.bus.Connect(ctx); err != nil {
		slog.Warn("bus unreachable", "err", err)
		s.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "the bubble is unreachable"),
			time.Now().Add(writeTimeout))
		return
	}
	defer s.bus.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.tend(ctx)
	s.readBrowser()
}

func (s *session) readBrowser() {
	s.ws.SetReadLimit(monolink.MaxFrame)
	s.ws.SetReadDeadline(time.Now().Add(readTimeout))
	s.ws.SetPongHandler(func(string) error { return s.ws.SetReadDeadline(time.Now().Add(readTimeout)) })
	for {
		_, data, err := s.ws.ReadMessage()
		if err != nil {
			return
		}
		m, err := monolink.Parse(strings.TrimSpace(string(data)))
		if err != nil || m.Version != monolink.V2 {
			continue // nothing to answer: a malformed frame has no id to answer with
		}
		if !s.allow() {
			s.answer(m, monolink.VerbErr, monolink.CodeBusy, "slow down")
			continue
		}
		s.fromBrowser(m)
	}
}

// allow spends one token of the browser's allowance.
func (s *session) allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.tokens = min(rateBurst, s.tokens+now.Sub(s.filled).Seconds()*ratePerSec)
	s.filled = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

// tend keeps the session honest while it lasts: pings the browser, ends it
// if the bus went away, forgets unanswered requests, and re-reads the
// person's grants — a grant revoked, or a session ended, reaches the phone.
func (s *session) tend(ctx context.Context) {
	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	grants := time.NewTicker(grantsEvery)
	defer grants.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			if !s.bus.Connected() {
				s.ws.Close()
				return
			}
			s.wmu.Lock()
			err := s.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout))
			s.wmu.Unlock()
			if err != nil {
				s.ws.Close()
				return
			}
			s.mu.Lock()
			for id, p := range s.pending {
				if time.Since(p.at) > pendingTTL {
					delete(s.pending, id)
				}
			}
			s.mu.Unlock()
		case <-grants.C:
			if s.who() != "" {
				s.readGrants()
			}
		}
	}
}

func (s *session) who() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user
}

// ─── browser to bus ──────────────────────────────────────────────────

func (s *session) fromBrowser(m monolink.Message) {
	if why := s.refuse(m); why != "" {
		s.answer(m, monolink.VerbErr, monolink.CodeDenied, why)
		return
	}
	id := busID()
	if m.To != monolink.All { // a roll call is answered by announcing, not by a reply
		s.mu.Lock()
		s.pending[id] = pending{browserID: m.ID, verb: m.Verb, noun: m.Noun, at: time.Now()}
		s.mu.Unlock()
	}
	out := monolink.Message{Version: monolink.V2, ID: id, From: s.bus.Address(),
		To: m.To, Verb: m.Verb, Noun: m.Noun, Args: m.Args}
	if err := s.bus.SendMessage(out); err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		s.answer(m, monolink.VerbErr, monolink.CodeState, "the bubble is unreachable")
	}
}

// refuse says why a frame may not go on the bus, or "" if it may.
func (s *session) refuse(m monolink.Message) string {
	switch m.Verb {
	case monolink.VerbPub, monolink.VerbReg, monolink.VerbFire, monolink.VerbOK, monolink.VerbErr:
		return "a panel neither announces nor answers"
	}
	to, err := monolink.ParseAddress(m.To)
	if err != nil || to.Bubble != "" {
		return "no such node"
	}
	s.mu.Lock()
	user, grants := s.user, s.grants
	s.mu.Unlock()

	if to.Node == marshal.Node {
		if user != "" {
			return "" // marshal judges its own requests
		}
		switch m.Verb + ":" + m.Noun {
		case "AUTH:USER", "AUTH:PROOF", "SET:SESSION":
			return ""
		case "AUTH:ENROL":
			return "the first person enrols at home"
		}
		return "sign in first"
	}
	if user == "" {
		return "sign in first"
	}
	if m.Verb == monolink.VerbPing {
		return ""
	}
	if to.Node == monolink.All {
		if m.Verb == monolink.VerbGet && m.Noun == monolink.VerbReg {
			return ""
		}
		return "not permitted"
	}
	if action := marshal.Action(to.Node, m.Verb, m.Noun); !marshal.Allowed(grants, action) {
		return "needs " + action
	}
	return ""
}

// answer replies to the browser in the name of the node it asked.
func (s *session) answer(m monolink.Message, verb, noun string, args ...string) {
	from := m.To
	if a, err := monolink.ParseAddress(m.To); err == nil {
		from = a.Node
	}
	s.toBrowser(monolink.Message{Version: monolink.V2, ID: m.ID, From: from, To: Panel,
		Verb: verb, Noun: noun, Args: args})
}

// ─── bus to browser ──────────────────────────────────────────────────

func (s *session) fromBus(req *monolink.Request) {
	m := req.Msg
	if m.Version != monolink.V2 {
		return
	}
	switch m.Verb {
	case monolink.VerbOK, monolink.VerbErr:
		s.mu.Lock()
		p, ok := s.pending[m.ID]
		delete(s.pending, m.ID)
		s.mu.Unlock()
		if !ok {
			return // not an answer to this browser
		}
		s.follow(p, m)
		m.ID = p.browserID
		s.toBrowser(m)

	case monolink.VerbPub, monolink.VerbReg:
		if m.To != monolink.All {
			return
		}
		s.mu.Lock()
		user, grants := s.user, s.grants
		s.mu.Unlock()
		if user == "" {
			return
		}
		from, err := monolink.ParseAddress(m.From)
		if err != nil {
			return
		}
		// A person sees the values they may read. What exists (REG) is not
		// a secret; what it currently is, may be.
		if m.Verb == monolink.VerbPub && !marshal.Allowed(grants, marshal.Action(from.Node, monolink.VerbGet, m.Noun)) {
			return
		}
		s.toBrowser(m)
	}
}

// follow watches marshal's answers about this session. A session opened or
// kept puts the person's name on everything sent from here on, and their
// grants in force; one ended or refused takes both off.
func (s *session) follow(p pending, m monolink.Message) {
	from, err := monolink.ParseAddress(m.From)
	if err != nil || from.Node != marshal.Node {
		return
	}
	asked := p.verb + ":" + p.noun
	switch {
	case m.Verb == monolink.VerbOK && m.Noun == marshal.NounSession && len(m.Args) == 3 &&
		(asked == "AUTH:PROOF" || asked == "SET:SESSION"):
		if marshal.ValidName(m.Args[1]) {
			s.adopt(m.Args[1])
		}
	case asked == "STOP:SESSION" && m.Verb == monolink.VerbOK,
		asked == "SET:SESSION" && m.Verb == monolink.VerbErr:
		s.drop()
	}
}

// adopt signs the person in here. Their grants are read before the browser
// hears it is signed in, so its next request is already judged by them.
func (s *session) adopt(user string) {
	s.mu.Lock()
	s.user, s.grants = user, nil
	s.mu.Unlock()
	if err := s.bus.SetActor(user); err != nil {
		s.drop()
		return
	}
	s.readGrants()
	slog.Info("signed in", "user", user)
}

func (s *session) drop() {
	s.mu.Lock()
	was := s.user
	s.user, s.grants = "", nil
	s.mu.Unlock()
	s.bus.SetActor("")
	if was != "" {
		slog.Info("signed out", "user", was)
	}
}

// readGrants asks marshal what the person may do. A refusal means their
// session has gone — ended elsewhere, or expired — and they are signed out.
func (s *session) readGrants() {
	user := s.who()
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	g, err := marshal.Grants(ctx, s.bus, user)
	var re *monolink.ReplyError
	switch {
	case errors.As(err, &re):
		s.drop()
	case err != nil:
		slog.Warn("grants unread", "user", user, "err", err) // keep what we had
	default:
		s.mu.Lock()
		if s.user == user {
			s.grants = g
		}
		s.mu.Unlock()
	}
}

func (s *session) toBrowser(m monolink.Message) {
	wire, err := m.Marshal()
	if err != nil {
		return
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := s.ws.WriteMessage(websocket.TextMessage, []byte(wire)); err != nil {
		s.ws.Close()
	}
}

// busID is a fresh id for a request portal forwards: random, so no two
// browsers' requests can share one and see each other's answers.
func busID() string {
	var b [8]byte
	rand.Read(b[:])
	const ids = 2821109907456 // 36^8, every 1..8-character id
	return strconv.FormatUint(binary.LittleEndian.Uint64(b[:])%ids, 36)
}
