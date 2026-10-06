// Package rtsp - auth.go: Digest and Basic authentication for RTSP.
package rtsp

import (
	"crypto/md5" //nolint:gosec // MD5 is required by the RTSP Digest scheme
	"crypto/rand"
	"fmt"
	"strings"
)

// .Auth implements RFC 2069/2617 Digest and Basic authentication for RTSP
// (UniFi Protect uses Digest).
type Auth struct {
	Username string
	Password string
	Realm    string
	Nonce    string
	// extra credential pairs accepted (e.g. Protect retries the ONVIF
	// adoption credentials on the RTSP URI - the camera shows up with
	// "no video" if these don't match).
	extra map[string]string
}

// NewAuth builds an auth handler with a fresh random nonce.
func NewAuth(username, password, realm string) *Auth {
	return &Auth{Username: username, Password: password, Realm: realm, Nonce: randomHex(16), extra: map[string]string{}}
}

// AddCredentials registers an additional accepted user:pass pair.
func (a *Auth) AddCredentials(user, pass string) {
	if a.extra == nil {
		a.extra = map[string]string{}
	}
	a.extra[user] = pass
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Challenge returns the WWW-Authenticate header value.
func (a *Auth) Challenge() string {
	return fmt.Sprintf("Digest realm=%q, nonce=%q", a.Realm, a.Nonce)
}

// Verify checks the Authorization header of a request.
func (a *Auth) Verify(header, method string) bool {
	if header == "" {
		return false
	}
	// "Basic <b64>" support
	if strings.HasPrefix(header, "Basic ") {
		return a.verifyBasic(strings.TrimPrefix(header, "Basic "))
	}
	if !strings.HasPrefix(header, "Digest ") {
		return false
	}
	params := parseAuthParams(strings.TrimPrefix(header, "Digest "))
	user := params["username"]
	resp := params["response"]
	uri := params["uri"]
	nonce := params["nonce"]
	nc := params["nc"]
	cnonce := params["cnonce"]
	qop := params["qop"]
	if resp == "" || nonce != a.Nonce {
		return false
	}
	pass, ok := a.passwordFor(user)
	if !ok {
		return false
	}
	ha1 := fmt.Sprintf("%x", md5.Sum([]byte(user+":"+a.Realm+":"+pass)))
	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(method+":"+uri)))
	var expected string
	if qop != "" {
		expected = md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		expected = md5hex(ha1 + ":" + nonce + ":" + ha2)
	}
	return strings.EqualFold(expected, resp)
}

// passwordFor resolves the expected password for a user (primary first, then
// any extra registered pairs).
func (a *Auth) passwordFor(user string) (string, bool) {
	if user == a.Username {
		return a.Password, true
	}
	if p, ok := a.extra[user]; ok {
		return p, true
	}
	return "", false
}

// verifyBasic checks "b64(user:pass)".
func (a *Auth) verifyBasic(b64 string) bool {
	dec, err := base64Decode(b64)
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(dec, ":")
	if !ok {
		return false
	}
	expected, ok := a.passwordFor(user)
	return ok && pass == expected
}

func md5hex(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func parseAuthParams(raw string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(raw, ",") {
		kv = strings.TrimSpace(kv)
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			continue
		}
		k := kv[:idx]
		v := strings.Trim(kv[idx+1:], `"`)
		out[k] = v
	}
	return out
}

func base64Decode(s string) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var vals []byte
	for _, c := range s {
		if c == '=' {
			break
		}
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return "", fmt.Errorf("bad base64")
		}
		vals = append(vals, byte(idx))
	}
	var out []byte
	for i := 0; i+3 < len(vals)+1 && i < len(vals); i += 4 {
		n := len(vals) - i
		b0 := vals[i]
		var b1, b2 byte
		if n > 1 {
			b1 = vals[i+1]
		}
		if n > 2 {
			b2 = vals[i+2]
		}
		out = append(out, b0<<2|b1>>4)
		if n > 2 {
			out = append(out, b1<<4|b2>>2)
		}
		if n > 3 {
			out = append(out, b2<<6|vals[i+3])
		}
	}
	return string(out), nil
}
