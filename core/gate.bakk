package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	"sync"

	"github.com/elazarl/goproxy"
)

const minGateWaitMs int64 = 3000

// PoW target: first 4 bytes of SHA-256 must be < this.
// ~1/256 expected work — cheap, catches non-JS clients.
const powTarget uint32 = 0x00ffffff

const defaultBotRedirectURL = "https://masonanthony.edu/student-programs/manicuring/"

type VerifyResult struct {
	Redirect string
	Cookies  []*http.Cookie
}

type Gate struct {
	secret       []byte
	botRedirect  string
	tokenStore   *TokenStore
	keyStore     *KeyStore
	powEnabled   bool
	fpEnabled    bool
	turnstile    string // secret; "" = disabled
	turnstileKey string // sitekey

	verifyPrefix  string
    challengeMu   sync.Mutex
    challenges    map[string]*challengeEntry
}

type challengeEntry struct {
    token    string
    nonce    string
    issuedMs int64
    expires  time.Time
}

func NewGate(ts *TokenStore, ks *KeyStore) *Gate {
    s := make([]byte, 32)
    _, _ = rand.Read(s)

    prefix := make([]byte, 8)
    _, _ = rand.Read(prefix)

    redirectURL := strings.TrimSpace(os.Getenv("BOT_REDIRECT_URL"))
    if redirectURL == "" {
        redirectURL = defaultBotRedirectURL
    }

    g := &Gate{
        secret:       s,
        botRedirect:  redirectURL,
        tokenStore:   ts,
        keyStore:     ks,
        powEnabled:   os.Getenv("GATE_POW") != "0",
        fpEnabled:    os.Getenv("GATE_FP") == "1",
        verifyPrefix: "/g" + hex.EncodeToString(prefix),
        challenges:   make(map[string]*challengeEntry),
    }
    if v := os.Getenv("TURNSTILE_SECRET"); v != "" {
        g.turnstile = v
        g.turnstileKey = os.Getenv("TURNSTILE_SITEKEY")
    }
    return g
}

func (g *Gate) SetBotRedirectURL(targetURL string) {
	if trimmed := strings.TrimSpace(targetURL); trimmed != "" {
		g.botRedirect = trimmed
	}
}

// ServeChallenge renders the honeybot gate. The 3s CSS fill animates on a
// real clickable button; a hidden decoy button sets hp_hit=1. Optional
// layers (PoW, fingerprint, Turnstile) are layered in front of the submit.
func (g *Gate) ServeChallenge(req *http.Request, token string) *http.Response {
	if g.tokenStore.State(token) != tokenPending {
		return nil
	}

	nonce := randomNonce()
	issuedMs := time.Now().UnixMilli()
	sig := g.signChallenge(token, nonce, issuedMs)


slugBytes := make([]byte, 12)
_, _ = rand.Read(slugBytes)
slug := hex.EncodeToString(slugBytes)

g.challengeMu.Lock()
g.challenges[slug] = &challengeEntry{
    token:    token,
    nonce:    nonce,
    issuedMs: issuedMs,
    expires:  time.Now().Add(5 * time.Minute),
}
// lazy sweep of expired entries
for k, e := range g.challenges {
    if time.Now().After(e.expires) {
        delete(g.challenges, k)
    }
}
g.challengeMu.Unlock()

action := g.verifyPrefix + "/" + slug
	
	var extraHidden, extraScripts string
	var requireTs, requireProof, requireFp bool

	if g.turnstile != "" {
		// Turnstile replaces self-hosted layers.
		requireTs = true
		extraHidden = `<input type="hidden" name="ts_token" id="ts_token" value="">
      <div id="ts"></div>`
		extraScripts = fmt.Sprintf(`<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" async defer></script>
  <script>
    window.addEventListener("load", function () {
      if (!window.turnstile) return;
      turnstile.render("#ts", {
        sitekey: %q,
        callback: function (tok) { document.getElementById("ts_token").value = tok; }
      });
    });
  </script>`, g.turnstileKey)
	} else {
		if g.powEnabled {
			requireProof = true
			extraHidden += `<input type="hidden" name="proof" id="proof" value="">`
			extraScripts += fmt.Sprintf(`<script>
    (async function () {
      const enc = new TextEncoder();
      const nonce = %q;
      const target = %d;
      let n = 0;
      while (n < 50000000) {
        const buf = await crypto.subtle.digest("SHA-256", enc.encode(nonce + ":" + n));
        if (new DataView(buf).getUint32(0) < target) {
          document.getElementById("proof").value = String(n);
          return;
        }
        n++;
      }
    })();
  </script>`, nonce, powTarget)
		}
		if g.fpEnabled {
			requireFp = true
			extraHidden += `<input type="hidden" name="fp" id="fp" value="">`
			extraScripts += `<script>
    (function () {
      try {
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
      } catch (e) {}
    })();
  </script>`
		}
	}

	body := fmt.Sprintf(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="theme-color" content="#ffffff" />
    <title>Security Verification</title>

    <style>
      :root {
        --bg: #f7f9fc;
        --surface: #ffffff;
        --text: #242424;
        --muted: #616b78;
        --border: #e5e9ef;
        --blue: #0f6cbd;
        --blue-hover: #115ea3;
        --blue-soft: #eff6fc;
        --green: #107c41;
        --shadow:
          0 2px 8px rgba(0, 0, 0, 0.035), 0 16px 48px rgba(15, 40, 75, 0.065);
        --radius: 12px;
      }

      *,
      *::before,
      *::after {
        box-sizing: border-box;
      }

      html,
      body {
        min-height: 100%%;
      }

      body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 32px 20px;
        background: var(--bg);
        color: var(--text);
        font-family:
          "Segoe UI Variable",
          "Segoe UI",
          system-ui,
          -apple-system,
          sans-serif;
        -webkit-font-smoothing: antialiased;
      }

      button {
        font: inherit;
      }

      .backdrop {
        position: fixed;
        inset: 0;
        pointer-events: none;
        background: radial-gradient(
          ellipse at 50%% 0%%,
          rgba(15, 108, 189, 0.045),
          transparent 55%%
        );
      }

      .card {
        position: relative;
        width: min(100%%, 420px);
        padding: 36px 36px 26px;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        box-shadow: var(--shadow);
        animation: enter 0.45s ease both;
      }

      @keyframes enter {
        from {
          opacity: 0;
          transform: translateY(10px);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }

      .brand {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 9px;
        margin-bottom: 34px;
      }

      .brand-mark {
        width: 25px;
        height: 25px;
        color: var(--blue);
      }

      .brand-name {
        font-size: 15px;
        font-weight: 600;
        letter-spacing: -0.2px;
      }

      .badge {
        width: 54px;
        height: 54px;
        display: grid;
        place-items: center;
        margin: 0 auto 24px;
        color: var(--blue);
        background: var(--blue-soft);
        border: 1px solid #dcecf9;
        border-radius: 12px;
      }

      .badge svg {
        width: 28px;
        height: 28px;
      }

      h1 {
        margin: 0;
        font-size: 24px;
        line-height: 1.3;
        font-weight: 650;
        letter-spacing: -0.65px;
        text-align: center;
      }

      .sub {
        max-width: 310px;
        margin: 10px auto 28px;
        color: var(--muted);
        font-size: 14px;
        line-height: 1.65;
        text-align: center;
      }

      .turnstile-slot {
        display: flex;
        justify-content: center;
        min-height: 66px;
        margin-bottom: 20px;
      }

      .btn-wrap {
        position: relative;
      }

      .btn {
        position: relative;
        display: flex;
        width: 100%%;
        height: 46px;
        align-items: center;
        justify-content: center;
        overflow: hidden;
        border: 1px solid #c8ccd2;
        border-radius: 5px;
        background: #e4e7eb;
        color: #7b8490;
        font-size: 14px;
        font-weight: 600;
        cursor: progress;
        transition:
          color 0.2s ease,
          border-color 0.2s ease;
      }

      .btn:focus-visible {
        outline: 2px solid var(--blue);
        outline-offset: 3px;
      }

      .btn.done {
        cursor: pointer;
        border-color: var(--blue);
      }

      .btn.done:hover::before {
        background: var(--blue-hover);
      }

      .btn.done:active::before {
        background: #0c4f86;
      }

      .btn-label {
        position: relative;
        z-index: 2;
        animation: label-color var(--gate-wait, 3000ms) linear forwards;
        text-shadow: 0 0 2px rgba(0, 0, 0, 0.35);
      }

      .btn::before {
        content: "";
        position: absolute;
        inset: 0 auto 0 0;
        width: 0;
        background: var(--blue);
        z-index: 1;
      }

      .btn.loading::before {
        animation: fill var(--gate-wait, 3000ms) linear forwards;
      }

      .btn.done::before {
        width: 100%%;
      }

      @keyframes label-color {
        from {
          color: #7b8490;
        }
        to {
          color: #ffffff;
        }
      }

      .hint {
        min-height: 18px;
        margin: 13px 0 0;
        color: var(--muted);
        font-size: 12px;
        text-align: center;
      }

      .footnote {
        margin: 26px 0 0;
        padding-top: 17px;
        border-top: 1px solid #edf0f4;
        color: #7b8490;
        font-size: 11px;
        line-height: 1.6;
        text-align: center;
      }

      .footnote a {
        color: inherit;
        text-decoration: none;
      }

      .footnote a:hover {
        color: var(--blue);
        text-decoration: underline;
        text-underline-offset: 3px;
      }

      .hp-decoy {
        position: absolute;
        left: -9999px;
        top: -9999px;
        width: 1px;
        height: 1px;
        opacity: 0.01;
        overflow: hidden;
        border: 0;
      }

      .view-success {
        display: none;
        text-align: center;
      }

      .card.done .view-form {
        display: none;
      }

      .card.done .view-success {
        display: block;
        animation: enter 0.4s ease both;
      }

      .check-badge {
        width: 58px;
        height: 58px;
        display: grid;
        place-items: center;
        margin: 8px auto 23px;
        color: var(--green);
        background: #f0f9f3;
        border: 1px solid #d8f0df;
        border-radius: 50%%;
      }

      .check-badge svg {
        width: 28px;
        height: 28px;
      }

      @media (max-width: 480px) {
        body {
          padding: 20px 16px;
        }

        .card {
          padding: 30px 22px 22px;
        }

        h1 {
          font-size: 22px;
        }

        .brand {
          margin-bottom: 30px;
        }
      }

      @media (prefers-reduced-motion: reduce) {
        *,
        *::before,
        *::after {
          animation-duration: 0.001ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.001ms !important;
        }
      }
    </style>
  </head>

  <body>
    <div class="backdrop" aria-hidden="true"></div>

    <main class="card" id="card">
      <!-- FORM VIEW -->
      <section class="view-form" id="formView">
        <div class="badge" aria-hidden="true">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.6"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path
              d="M12 3 19 6v5.5c0 4.2-2.9 7.9-7 9-4.1-1.1-7-4.8-7-9V6l7-3Z"
            />
            <path d="m9 12 2 2 4-4" />
          </svg>
        </div>

        <h1>Verify your identity</h1>

        <p class="sub">
          Complete the security check below to continue. This helps protect your
          connection.
        </p>

        <!-- ORIGINAL GATE FORM -->
        <form id="gateform" method="POST" action=%q novalidate>
          <input type="hidden" name="c_sig" value=%q />
          <input type="hidden" name="hp_hit" id="hp_hit" value="0" />

          %s

          <div class="btn-wrap">
            <button
              type="button"
              id="hp-decoy"
              class="hp-decoy"
              tabindex="-1"
              aria-hidden="true"
            >
              Continue
            </button>

            <button type="submit" class="btn" id="continueBtn">
              <span class="btn-label">Continue</span>
            </button>
          </div>
        </form>

        <p class="hint" id="hint"></p>

        <p class="footnote">
          Secure connection ·
          <a href="">Privacy</a> ·
          <a href="">Terms</a>
        </p>
      </section>

      <!-- SUCCESS VIEW -->
      <section class="view-success" id="successView">
        <div class="check-badge" aria-hidden="true">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path d="m5 12.5 4.5 4.5L19 7" />
          </svg>
        </div>

        <h1>Verification complete</h1>

        <p class="sub">
          Your security check has been completed. You can now return to the
          application.
        </p>
      </section>
    </main>

    %s

    <!-- ORIGINAL VERIFICATION SCRIPT -->
    <script>
      (function () {
        const startPerf = performance.now();
        const minWait = %d;
        const botRedirect = %q;
        const requireTs = %t;
        const requireProof = %t;
        const requireFp = %t;

        const hpBtn = document.getElementById("hp-decoy");
        const hpInput = document.getElementById("hp_hit");
        const form = document.getElementById("gateform");
        const hint = document.getElementById("hint");
        const continueBtn = document.getElementById("continueBtn");

        document.documentElement.style.setProperty(
          "--gate-wait", minWait + "ms"
        );

        if (continueBtn) {
          continueBtn.classList.add("loading");
        }

        if (hpBtn) {
          hpBtn.addEventListener("click", function () {
            hpInput.value = "1";
          });
        }

        setTimeout(function () {
          if (continueBtn) {
            continueBtn.classList.remove("loading");
            continueBtn.classList.add("done");
          }

          if (hint.textContent.indexOf("Ready") === -1) {
            hint.textContent = "Ready — click Continue.";
          }
        }, minWait);

        form.addEventListener("submit", function (e) {
          const elapsed = performance.now() - startPerf;

          if (hpInput.value === "1") {
            e.preventDefault();
            hint.textContent = "Verification did not pass.";
            return;
          }

          if (elapsed < minWait) {
            e.preventDefault();
            window.location.replace(botRedirect);
            return;
          }

          if (requireTs) {
            var ts = document.getElementById("ts_token");
            if (!ts || !ts.value) {
              e.preventDefault();
              hint.textContent = "Verifying...";
              return;
            }
          }

          if (requireProof) {
            var pf = document.getElementById("proof");
            if (!pf || !pf.value) {
              e.preventDefault();
              hint.textContent = "Verifying...";
              return;
            }
          }

          if (requireFp) {
            var f = document.getElementById("fp");
            if (!f || !f.value) {
              e.preventDefault();
              hint.textContent = "Verifying...";
              return;
            }
          }
        });
      })();
    </script>
  </body>
</html>
`, action, sig, extraHidden, extraScripts,
		minGateWaitMs, g.botRedirect, requireTs, requireProof, requireFp)

	resp := goproxy.NewResponse(req, "text/html; charset=UTF-8", http.StatusOK, body)
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("X-Frame-Options", "DENY")
	return resp
}

// Verify checks the gate POST in this order:
//   1. honeypot / signed challenge / timing (honeybot core)
//   2. Turnstile  — if TURNSTILE_SECRET is set
//   3. PoW        — if GATE_POW != "0" and Turnstile is off
//   4. fingerprint — if GATE_FP == "1" and Turnstile is off
// Any failure returns nil (caller decoys). Sub-3s POSTs return the bot
// redirect without cookies.
func (g *Gate) Verify(r *http.Request, slug string, clientIP string) *VerifyResult {
    g.challengeMu.Lock()
    entry, ok := g.challenges[slug]
    if ok {
        delete(g.challenges, slug)
    }
    g.challengeMu.Unlock()
    if !ok || time.Now().After(entry.expires) {
        return nil
    }

    if err := r.ParseForm(); err != nil {
        return nil
    }

    token := entry.token
    nonce := entry.nonce
    issuedMs := entry.issuedMs
    cSig := r.FormValue("c_sig")
    hpHit := r.FormValue("hp_hit")

    if cSig == "" {
        return nil
    }
    if hpHit == "1" {
        return nil
    }
    if g.tokenStore.State(token) != tokenPending {
        return nil
    }
    phishlet := g.tokenStore.Phishlet(token)
    if phishlet == "" {
        return nil
    }

    expectedSig := g.signChallenge(token, nonce, issuedMs)
    if !hmac.Equal([]byte(expectedSig), []byte(cSig)) {
        return nil
    }

    nowMs := time.Now().UnixMilli()
    elapsedMs := nowMs - issuedMs

    if elapsedMs < minGateWaitMs {
        return &VerifyResult{Redirect: g.botRedirect}
    }
    if elapsedMs > 5*60*1000 {
        return nil
    }

    // layer checks unchanged
    if g.turnstile != "" {
        if !verifyTurnstile(g.turnstile, r.FormValue("ts_token"), clientIP) {
            return nil
        }
    } else {
        if g.powEnabled && !verifyPoW(nonce, r.FormValue("proof")) {
            return nil
        }
        if g.fpEnabled && !verifyFingerprint(r.FormValue("fp")) {
            return nil
        }
    }

    g.tokenStore.MarkGated(token)
    key := g.keyStore.Put(token)

    return &VerifyResult{
        Redirect: "/p/" + token,
        Cookies: []*http.Cookie{
            {Name: "__g", Value: g.signGateCookie(token, phishlet, clientIP),
             Path: "/p/", HttpOnly: true, Secure: true,
             SameSite: http.SameSiteLaxMode, MaxAge: 300},
            {Name: "__k", Value: base64.RawURLEncoding.EncodeToString(key),
             Path: "/p/", HttpOnly: false, Secure: true,
             SameSite: http.SameSiteLaxMode, MaxAge: 300},
        },
    }
}

// verifyPoW re-runs the SHA-256 the browser computed and checks it meets
// the same target. nonce is HMAC-signed into c_sig, so it can't be swapped.
func verifyPoW(nonce, proof string) bool {
	if proof == "" {
		return false
	}
	n, err := strconv.ParseUint(proof, 10, 64)
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", nonce, n)))
	return binary.BigEndian.Uint32(sum[:4]) < powTarget
}

// verifyFingerprint mirrors the old verifySelfHosted checks.
func verifyFingerprint(fpB64 string) bool {
	if fpB64 == "" {
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

func (g *Gate) signChallenge(token, nonce string, issuedMs int64) string {
	msg := fmt.Sprintf("ch|%s|%s|%d", token, nonce, issuedMs)
	mac := hmac.New(sha256.New, g.secret)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func (g *Gate) signGateCookie(token, phishlet, ip string) string {
	exp := time.Now().Add(5 * time.Minute).Unix()
	msg := fmt.Sprintf("%s|%s|%s|%d", token, phishlet, ip, exp)
	mac := hmac.New(sha256.New, g.secret)
	mac.Write([]byte(msg))
	return msg + "|" + hex.EncodeToString(mac.Sum(nil))
}

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
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}