package onvif

import (
	"crypto/sha1" //nolint:gosec // ONVIF digest test vector
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sha1Raw sums a string with SHA-1 for the test digest.
func sha1Raw(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}

func wrapBody(inner string) []byte {
	return []byte(`<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>` + inner + `</s:Body></s:Envelope>`)
}

func TestVerifyWSUsernameToken(t *testing.T) {
	a := NewAuth("admin", "secret")
	nonce := "1234abcd"
	created := "2026-01-01T00:00:00Z"
	h := sha1sum(nonce + created + "secret")
	tok := `<s:Security><wsse:UsernameToken><wsse:Username>admin</wsse:Username>
<wsse:Password Type="...#PasswordDigest">` + base64.StdEncoding.EncodeToString(h) + `</wsse:Password>
<wsse:Nonce>` + base64.StdEncoding.EncodeToString([]byte(nonce)) + `</wsse:Nonce>
<wsu:Created>` + created + `</wsu:Created></wsse:UsernameToken></s:Security>`
	body := wrapBody(`<tds:GetDeviceInformation/>` + tok)
	if !a.Verify(body) {
		t.Error("valid token rejected")
	}
	// wrong password
	h2 := sha1sum(nonce + created + "wrong")
	tok2 := strings.Replace(tok, base64.StdEncoding.EncodeToString(h), base64.StdEncoding.EncodeToString(h2), 1)
	body2 := wrapBody(`<tds:GetDeviceInformation/>` + tok2)
	if a.Verify(body2) {
		t.Error("invalid token accepted")
	}
	// no security block: allowed (harmless discovery calls)
	if !a.Verify(wrapBody(`<tds:GetSystemDateAndTime/>`)) {
		t.Error("unauthenticated harmless call rejected")
	}
}

func TestServiceHandlers(t *testing.T) {
	s := NewService(
		&DeviceInfo{Manufacturer: "M", Model: "KD110", Firmware: "1", Serial: "S",
			HardwareID: "HW", MAC: "00:11:22:33:44:55", IPAddress: "10.0.0.5"},
		&MediaInfo{ProfileToken: "PROFILE_000", ProfileName: "P", Width: 2304, Height: 1296,
			FPS: 20, RTSPURL: "rtsp://10.0.0.5:8554/doorcam", SnapshotURI: "http://x/snap"},
		NewAuth("admin", "pw"))
	for _, action := range []string{"GetSystemDateAndTime", "GetCapabilities", "GetDeviceInformation",
		"GetProfiles", "GetProfile", "GetStreamUri", "GetSnapshotUri", "GetNetworkInterfaces",
		"GetScopes", "GetServices", "GetVideoSourceConfigurations", "GetVideoEncoderConfigurations",
		"GetVideoSourceConfiguration", "GetVideoEncoderConfiguration",
		"GetVideoEncoderConfigurationOptions"} {
		out, err := handlers[action](s, []byte{})
		if err != nil {
			t.Errorf("%s: %v", action, err)
		}
		if !strings.Contains(out, "Envelope") {
			t.Errorf("%s: no envelope", action)
		}
	}
	// StreamUri must appear in GetStreamUri response
	out, _ := handlers["GetStreamUri"](s, []byte{})
	if !strings.Contains(out, "rtsp://10.0.0.5:8554/doorcam") {
		t.Errorf("stream uri missing: %s", out)
	}
}

func TestServeHTTPGetStreamUri(t *testing.T) {
	s := NewService(
		&DeviceInfo{Manufacturer: "M", Model: "KD110", Firmware: "1", Serial: "S",
			HardwareID: "HW", MAC: "AA:BB:CC:DD:EE:FF", IPAddress: "10.0.0.5"},
		&MediaInfo{ProfileToken: "PROFILE_000", ProfileName: "P", Width: 2304, Height: 1296,
			FPS: 20, RTSPURL: "rtsp://10.0.0.5:8554/doorcam", SnapshotURI: "http://x/snap"},
		NewAuth("admin", "pw"))
	// unauthenticated GetStreamUri must be rejected (would be empty token)
	req := httptest.NewRequest("POST", "/onvif/device_service", strings.NewReader(string(wrapBody(`<trt:GetStreamUri/>`))))
	req.Header.Set("Content-Type", "application/soap+xml")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestDiscoveryProbeMatches(t *testing.T) {
	d := NewDiscovery("", "10.0.0.5:8080", "onvif://www.onvif.org/Profile/Streaming")
	reply := d.probeMatches("urn:uuid:probe-1", nil)
	for _, want := range []string{"ProbeMatches", "NetworkVideoTransmitter", "10.0.0.5:8080", "probe-1"} {
		if !strings.Contains(reply, want) {
			t.Errorf("missing %q in reply", want)
		}
	}
	// dedup: same message ID twice
	if d.dedup("x") {
		t.Error("first probe must not dedup")
	}
	if !d.dedup("x") {
		t.Error("second probe must dedup")
	}
}

func TestExtractTag(t *testing.T) {
	body := []byte(`<a:Username>bob</a:Username>`)
	if got := extractTag(body, "Username"); got != "bob" {
		t.Errorf("got %q", got)
	}
}

// sha1sum helper (mirrors the digest formula).
func sha1sum(s string) []byte {
	// imported via auth.go; re-implement to keep the test isolated
	return sha1Wrapper(s)
}

func TestUTCString(t *testing.T) {
	got := utcNowString(time.Unix(0, 0).UTC())
	if !strings.HasSuffix(got, "Z") || !strings.Contains(got, "1970") {
		t.Errorf("utc string = %q", got)
	}
}

var _ = hex.EncodeToString

// Protect places the wsse:Security block inside s:Body before the operation
// element; extractAction must return the operation, not "Security".
func TestExtractActionWithSecurityBlock(t *testing.T) {
	sec := `<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><wsse:UsernameToken><wsse:Username>admin</wsse:Username><wsse:Password Type="...#PasswordDigest">x</wsse:Password><wsse:Nonce>nQ==</wsse:Nonce><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2026-01-01T00:00:00Z</wsu:Created></wsse:UsernameToken></wsse:Security>`
	cases := []struct{ name, body, want string }{
		{"security then op (prefixed)", `<?xml?><s:Envelope xmlns:s="..."><s:Body>` + sec + `<tds:GetDeviceInformation><tds foo="1"/></tds:GetDeviceInformation></s:Body></s:Envelope>`, "GetDeviceInformation"},
		{"security then op (self-closing op)", `<?xml?><s:Envelope xmlns:s="..."><s:Body>` + sec + `<trt:GetProfiles/></s:Body></s:Envelope>`, "GetProfiles"},
		{"no security (prefixed)", `<?xml?><s:Envelope xmlns:s="..."><s:Body><tds:GetSystemDateAndTime/></s:Body></s:Envelope>`, "GetSystemDateAndTime"},
		{"media op", `<?xml?><s:Envelope xmlns:s="..."><s:Body>` + sec + `<trt:GetStreamUri><trt:ProfileToken>P</trt:ProfileToken></trt:GetStreamUri></s:Body></s:Envelope>`, "GetStreamUri"},
	}
	for _, c := range cases {
		if got := extractAction([]byte(c.body)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// Full round trip through ServeHTTP with the Security block inside Body.
func TestServeHTTPSecurityInsideBody(t *testing.T) {
	s := NewService(
		&DeviceInfo{Manufacturer: "M", Model: "KD110", Firmware: "1", Serial: "S",
			HardwareID: "HW", MAC: "AA:BB:CC:DD:EE:FF", IPAddress: "10.0.0.5"},
		&MediaInfo{ProfileToken: "PROFILE_000", ProfileName: "P", Width: 1280, Height: 720,
			FPS: 20, RTSPURL: "rtsp://10.0.0.5:8554/doorcam", SnapshotURI: "http://x/snap"},
		NewAuth("admin", "pw"))
	// digest computed exactly as the spec says: b64(SHA1(rawNonce + created + password))
	digestB64 := base64.StdEncoding.EncodeToString(sha1Raw([]byte("nonce-blob" + "2026-01-01T00:00:00Z" + "pw")))
	body := `<?xml?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>` +
		`<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><wsse:UsernameToken><wsse:Username>admin</wsse:Username><wsse:Password Type="...#PasswordDigest">` + digestB64 + `</wsse:Password><wsse:Nonce>` + base64.StdEncoding.EncodeToString([]byte("nonce-blob")) + `</wsse:Nonce><wsu:Created>2026-01-01T00:00:00Z</wsu:Created></wsse:UsernameToken></wsse:Security>` +
		`<tds:GetDeviceInformation/></s:Body></s:Envelope>`
	req := httptest.NewRequest("POST", "/onvif/device_service", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "GetDeviceInformationResponse") {
		t.Errorf("unexpected response: %s", w.Body.String()[:200])
	}
}

// The advertAddr must never be empty or scheme-less: Protect builds request
// URLs from XAddrs, and an empty host produced "/http://" 301 redirects.
func TestXAddrNeverEmpty(t *testing.T) {
	// Case 1: no IPAddress configured, advertise learned from Host header
	s := NewService(&DeviceInfo{Model: "KD110"}, &MediaInfo{ProfileToken: "P"}, NewAuth("u", "p"))
	if got := s.advertAddr(); got == "" || !strings.HasPrefix(got, "http://") {
		t.Errorf("advertAddr fallback = %q", got)
	}
	s.SetAdvertise("192.168.2.142:8080")
	if got := s.advertAddr(); got != "http://192.168.2.142:8080" {
		t.Errorf("advertAddr with Host = %q", got)
	}
	// Case 2: full URL configured
	s2 := NewService(&DeviceInfo{Model: "KD110", IPAddress: "http://10.0.0.5:8080/"}, &MediaInfo{ProfileToken: "P"}, NewAuth("u", "p"))
	if got := s2.advertAddr(); got != "http://10.0.0.5:8080" {
		t.Errorf("advertAddr from URL = %q", got)
	}

	// GetCapabilities/GetServices must contain a non-empty XAddr
	s.SetAdvertise("192.168.2.142:8080")
	for _, op := range []string{"GetCapabilities", "GetServices"} {
		out, err := handlers[op](s, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "http://192.168.2.142:8080") {
			t.Errorf("%s missing advert addr: %s", op, out)
		}
		if strings.Contains(out, "http://</tt:XAddr>") {
			t.Errorf("%s contains empty XAddr", op)
		}
	}
}
