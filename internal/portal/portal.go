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
//   - Until then it may only sign in, with a passkey, or take up an
//     invitation. After, everything it sends is checked
//     against the person's grants, here — enforced, not advised (SPEC §24),
//     because the internet is not the household — and again at the hub,
//     which holds the connection to the ticket marshal signed for the
//     session (SECURITY.txt §5).
//   - It hears only the answers to its own requests, and the announcements
//     of what its person may read. Nobody else's traffic.
package portal

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MrZloHex/monolink"
	"github.com/MrZloHex/monolink/marshal"
)

// Panel is the node every browser speaks as. The challenges a browser's
// passkey answers are marshal's to this panel.
const Panel = "MONOWEB"

const (
	pingEvery    = 30 * time.Second
	readTimeout  = 2 * pingEvery
	writeTimeout = 5 * time.Second
	pendingTTL   = time.Minute     // an unanswered request is forgotten after this
	ticketEvery  = 4 * time.Minute // how often a signed-in session renews its ticket; one lasts ten
	askTimeout   = 5 * time.Second
	rateBurst    = 40 // frames a browser may send at once
	ratePerSec   = 20 // and then per second

	// Each browser is a socket anyone may open, so what is rationed per
	// socket alone is not rationed: signing in and taking up invitations are
	// rationed per internet address too. A stranger may try a few; not fill
	// marshal's challenges, lock its invitations, or take every socket.
	signInWithin    = 2 * time.Minute // a socket nobody signs in on is closed after this
	maxPerAddress   = 8               // sockets from one internet address at once
	challengeBurst  = 10              // AUTH:CHALLENGE from one address at once
	challengePerSec = 1.0 / 6         // and then ten a minute
	redeemBurst     = 5               // AUTH:REDEEM from one address at once
	redeemPerSec    = 1.0 / 180       // and then one every three minutes
	maxVisitors     = 4096            // addresses remembered
	visitorTTL      = 30 * time.Minute
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
	visitors map[string]*visitor // by visitorKey
}

// visitor is one internet address, and what it may still try.
type visitor struct {
	sockets    int
	seen       time.Time // when its last socket closed
	challenges bucket
	redeems    bucket
}

// bucket is an allowance that refills: burst at once, then perSec.
type bucket struct {
	left float64
	at   time.Time
}

func (b *bucket) take(now time.Time, burst, perSec float64) bool {
	if b.at.IsZero() {
		b.left = burst
	} else {
		b.left = min(burst, b.left+now.Sub(b.at).Seconds()*perSec)
	}
	b.at = now
	if b.left < 1 {
		return false
	}
	b.left--
	return true
}

// visitorKey is whom r comes from, as rationing counts: its address, or for
// IPv6 its /64, which one household — or one attacker — holds whole. "" for
// the home network, the tunnel and the machine itself, which are not
// rationed: a router looping the household's phones back in from the LAN
// shows them all as one address.
func visitorKey(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	a := ap.Addr().Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() {
		return ""
	}
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// visitor is key's, made if need be; nil when too many are remembered. Call
// with mu held.
func (p *Portal) visitor(key string, now time.Time) *visitor {
	if v := p.visitors[key]; v != nil {
		return v
	}
	if len(p.visitors) >= maxVisitors {
		for k, v := range p.visitors {
			if v.sockets == 0 && now.Sub(v.seen) > visitorTTL {
				delete(p.visitors, k)
			}
		}
		if len(p.visitors) >= maxVisitors {
			return nil
		}
	}
	v := &visitor{}
	p.visitors[key] = v
	return v
}

func New(opt Options) *Portal {
	if opt.MaxSessions <= 0 {
		opt.MaxSessions = 32
	}
	p := &Portal{opt: opt, visitors: map[string]*visitor{}}
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
	key := visitorKey(r)
	p.mu.Lock()
	var v *visitor
	full := p.sessions >= p.opt.MaxSessions
	if !full && key != "" {
		v = p.visitor(key, time.Now())
		full = v == nil || v.sockets >= maxPerAddress
	}
	if !full {
		p.sessions++
		if v != nil {
			v.sockets++
		}
	}
	p.mu.Unlock()
	if full {
		http.Error(w, "too many sessions", http.StatusServiceUnavailable)
		return
	}
	defer func() {
		p.mu.Lock()
		p.sessions--
		if v != nil {
			v.sockets--
			v.seen = time.Now()
		}
		p.mu.Unlock()
	}()

	ws, err := p.up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	now := time.Now()
	s := &session{p: p, ws: ws, from: v, pending: map[string]pending{}, tokens: rateBurst, filled: now, anonSince: now}
	s.run(r.Context())
}

// ─── one browser ─────────────────────────────────────────────────────

type pending struct {
	browserID  string
	verb, noun string
	at         time.Time
}

type session struct {
	p    *Portal
	ws   *websocket.Conn
	wmu  sync.Mutex
	bus  *monolink.Client
	from *visitor // nil from the home network

	mu        sync.Mutex
	user      string
	grants    []string
	token     string             // the person's session, kept to renew the ticket
	until     time.Time          // when the ticket at the hub runs out
	anonSince time.Time          // when nobody was last signed in here
	pending   map[string]pending // by the id portal gave the request on the bus
	tokens    float64
	filled    time.Time
}

// inboxSize is how many frames from the bus may wait for one browser.
const inboxSize = 1024

func (s *session) run(ctx context.Context) {
	defer s.ws.Close()
	// Frames are taken from the inbox, in the order the hub sent them, not
	// through a handler: monolink runs each handler on its own goroutine,
	// so two PUBs of one value could reach the browser swapped.
	s.bus = monolink.New(Panel, s.p.opt.HubURL,
		append([]monolink.Option{monolink.WithDialect(monolink.V2), monolink.WithReconnect(0), monolink.WithInbox(inboxSize)}, s.p.opt.Dial...)...)
	if err := s.bus.Connect(ctx); err != nil {
		slog.Warn("bus unreachable", "err", err)
		s.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "the bubble is unreachable"),
			time.Now().Add(writeTimeout))
		return
	}
	defer s.bus.Close()
	inbox := s.bus.Inbox()
	go func() {
		for m := range inbox { // ends when Close closes it
			s.fromBus(m)
		}
	}()

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
// if the bus went away, forgets unanswered requests, and renews the person's
// ticket — a grant revoked, or a session ended, reaches the phone.
func (s *session) tend(ctx context.Context) {
	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	renew := time.NewTicker(ticketEvery)
	defer renew.Stop()
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
			lapsed := s.user != "" && time.Now().After(s.until)
			idle := s.user == "" && time.Since(s.anonSince) > signInWithin
			s.mu.Unlock()
			if idle {
				s.ws.Close() // a socket held open without anyone on it is a slot taken
				return
			}
			if lapsed {
				s.drop() // the ticket ran out and could not be renewed
			}
		case <-renew.C:
			if s.who() != "" {
				s.renewTicket()
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
	if !s.rationed(m) {
		s.answer(m, monolink.VerbErr, monolink.CodeBusy, "too many tries from here; wait a while")
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
		switch m.Verb + ":" + m.Noun {
		case "AUTH:CHALLENGE", "AUTH:PASSKEY", "AUTH:REDEEM", "SET:SESSION":
			return ""
		case "AUTH:ENROL":
			return "the first person enrols at home"
		case "AUTH:KEY":
			return "a browser signs in with a passkey"
		}
		if user != "" {
			return "" // marshal judges its own requests
		}
		return "sign in first"
	}
	if user == "" {
		return "sign in first"
	}
	if m.Verb == monolink.VerbPing {
		if to.Node != monolink.All && m.Noun == monolink.VerbPing && len(m.Args) == 0 {
			return "" // are you there — which asks nothing else of a node
		}
		return "not permitted" // and the hub would refuse it
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

// rationed spends what m costs from this browser's internet address, and
// reports whether there was enough: a challenge, or a try at an invitation.
func (s *session) rationed(m monolink.Message) bool {
	if s.from == nil {
		return true
	}
	to, err := monolink.ParseAddress(m.To)
	if err != nil || to.Node != marshal.Node {
		return true
	}
	now := time.Now()
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	switch m.Verb + ":" + m.Noun {
	case "AUTH:CHALLENGE":
		return s.from.challenges.take(now, challengeBurst, challengePerSec)
	case "AUTH:REDEEM":
		return s.from.redeems.take(now, redeemBurst, redeemPerSec)
	}
	return true
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

func (s *session) fromBus(m monolink.Message) {
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
		if err := s.follow(p, m); err != nil {
			m = monolink.Message{Version: monolink.V2, From: m.From, To: m.To, Verb: monolink.VerbErr,
				Noun: monolink.CodeState, Args: []string{err.Error()}}
		}
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
//
// It returns an error when a session marshal opened could not be taken up
// here: the browser is then told so, rather than that it is signed in.
func (s *session) follow(p pending, m monolink.Message) error {
	from, err := monolink.ParseAddress(m.From)
	if err != nil || from.Node != marshal.Node {
		return nil
	}
	asked := p.verb + ":" + p.noun
	switch {
	case m.Verb == monolink.VerbOK && m.Noun == marshal.NounSession && len(m.Args) == 3 &&
		(asked == "AUTH:PASSKEY" || asked == "AUTH:REDEEM" || asked == "SET:SESSION"):
		if marshal.ValidName(m.Args[1]) {
			return s.adopt(m.Args[1], m.Args[0])
		}
	case asked == "STOP:SESSION" && m.Verb == monolink.VerbOK,
		asked == "SET:SESSION" && m.Verb == monolink.VerbErr:
		s.drop()
	}
	return nil
}

// adopt signs the person in here. marshal's ticket for their session goes to
// the hub first, so the connection may act for them before the browser hears
// it is signed in; their grants are the ticket's.
func (s *session) adopt(user, token string) error {
	t, err := s.ticket(token)
	if err == nil && t.Person != user {
		err = fmt.Errorf("a ticket for %s", t.Person)
	}
	if err != nil {
		s.drop()
		slog.Warn("no ticket", "user", user, "err", err)
		return errors.New("signed in, but the hub did not take the ticket")
	}
	s.mu.Lock()
	s.user, s.token, s.grants, s.until = user, token, t.Grants, t.Expires
	s.mu.Unlock()
	if err := s.bus.SetActor(user); err != nil {
		s.drop()
		return err
	}
	slog.Info("signed in", "user", user)
	return nil
}

func (s *session) ticket(token string) (marshal.Ticket, error) {
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	return marshal.Ticketed(ctx, s.bus, token)
}

// renewTicket asks for a fresh ticket well before the one at the hub runs
// out. A refusal means the session has gone — ended, expired, its key
// removed, its person removed — and they are signed out here too.
func (s *session) renewTicket() {
	s.mu.Lock()
	user, token := s.user, s.token
	s.mu.Unlock()
	t, err := s.ticket(token)
	var re *monolink.ReplyError
	switch {
	case errors.As(err, &re):
		s.drop()
	case err != nil:
		slog.Warn("ticket not renewed", "user", user, "err", err) // the old one runs out by itself
	default:
		s.mu.Lock()
		if s.user == user {
			s.grants, s.until = t.Grants, t.Expires
		}
		s.mu.Unlock()
	}
}

func (s *session) drop() {
	s.mu.Lock()
	was := s.user
	s.user, s.token, s.grants, s.until = "", "", nil, time.Time{}
	if was != "" {
		s.anonSince = time.Now()
	}
	s.mu.Unlock()
	s.bus.SetActor("")
	if was != "" {
		go func() { // take the ticket off at the hub too; the connection may already be gone
			ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
			defer cancel()
			marshal.DropTicket(ctx, s.bus)
		}()
		slog.Info("signed out", "user", was)
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
