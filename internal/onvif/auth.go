// Package onvif implements the server side (device + media service) needed
// for UniFi Protect to adopt the doorbell: a SOAP/HTTP service responding to
// the standard ONVIF operations plus a WS-Discovery responder so the camera
// shows up in Protect's third-party discovery.
package onvif

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // ws-username token auth is defined with SHA-1
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
)

// Auth verifies ONVIF ws-username token credentials.
type Auth struct {
	Username string
	Password string
	// AllowUnauthenticated allows GetSystemDateAndTime/GetCapabilities etc
	AllowUnauthenticated bool
}

// NewAuth builds the auth handler.
func NewAuth(user, pass string) *Auth {
	return &Auth{Username: user, Password: pass, AllowUnauthenticated: true}
}

// WSUsernameToken is roughly:
//
//	<Security><UsernameToken><Username>..</Username>
//	<Password Type="..Digest">b64(digest)</Password><Nonce>b64</Nonce>
//	<Created>2026-01-01T00:00:00Z</Created></UsernameToken></Security>
//
// digest = base64(SHA1(nonce + created + password))
type wsSecurity struct {
	Username string
	Password string
	Nonce    string
	Created  string
}

// tagValueRe matches `<prefix:Tag ...attrs...>value<`. The `>` after the
// attribute group guarantees the local name is exact (not "UsernameToken").
var tagValueRe = regexp.MustCompile(`(?i)<[^<>\s:]+:([A-Za-z]+)(?:\s[^>]*)?>([^<]*)<`)

// tagValue finds the value of the first element with the given local name.
func tagValue(body []byte, name string) string {
	for _, m := range tagValueRe.FindAllSubmatch(body, -1) {
		if strings.EqualFold(string(m[1]), name) {
			return string(m[2])
		}
	}
	return ""
}

// recvUser returns the presented username (for logging only).
func (a *Auth) recvUser(body []byte) string {
	return tagValue(body, "Username")
}

// Verify checks the request body for a ws-username token. Failed lookups
// return false; matching is constant-time.
func (a *Auth) Verify(body []byte) bool {
	user := tagValue(body, "Username")
	if user == "" {
		return a.AllowUnauthenticated
	}
	if user != a.Username {
		return false
	}
	pw := tagValue(body, "Password")
	nonce := tagValue(body, "Nonce")
	created := tagValue(body, "Created")
	if pw == "" || nonce == "" || created == "" {
		// username without a full token: treat as unauthenticated
		return a.AllowUnauthenticated
	}
	// Some clients send the raw (non-b64) nonce; try both decodings.
	rawNonce, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		rawNonce = []byte(nonce)
	}
	h := sha1.New() //nolint:gosec // ONVIF spec mandates SHA-1
	h.Write(rawNonce)
	h.Write([]byte(created))
	h.Write([]byte(a.Password))
	expected := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(pw)) == 1 {
		return true
	}
	// Tolerance: a few clients compute the digest over the *base64* nonce
	// string instead of the decoded bytes.
	h2 := sha1.New() //nolint:gosec // ONVIF spec mandates SHA-1
	h2.Write([]byte(nonce))
	h2.Write([]byte(created))
	h2.Write([]byte(a.Password))
	return subtle.ConstantTimeCompare([]byte(base64.StdEncoding.EncodeToString(h2.Sum(nil))), []byte(pw)) == 1
}

// extractTag pulls the inner text of a namespaced tag from SOAP XML.
func extractTag(body []byte, tag string) string {
	return tagValue(body, tag)
}

// randomHex produces a nonce string.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// utcNowString returns an xsd:datetime with 'Z' suffix.
func utcNowString(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// utcTimePtr is used for header timestamps in responses.
func utcTimePtr(t time.Time) time.Time { return t }
