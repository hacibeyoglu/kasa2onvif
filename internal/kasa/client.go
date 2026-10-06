// Package kasa implements a client for the TP-Link Kasa camera private
// streaming protocol (used by KD110, KC200, KC401, KC420WS, EC71, ...).
//
// The stream URL is:
//
//	https://host:19443/https/stream/mixed?video=h264&audio=g711&resolution=hd
//
// The camera answers with HTTP/1.0 + Transfer-Encoding: chunked (out of
// standard) and content type multipart/x-mixed-replace with boundary
// "data-boundary--". Parts carry:
//
//	Content-Type: video/x-h264   -> H.264 Annex-B access unit
//	Content-Type: audio/g711u    -> G.711 mu-law chunk
//	X-Timestamp: <seconds>       -> presentation timestamp (float, seconds)
//	Content-Length: <n>
//
// Authentication is HTTP Basic. Per the reverse engineering notes the
// username is the url-escaped account e-mail and the password is the
// base64-encoded account password; some firmware versions however accept the
// plain credentials, so the caller can retry with the other variant on 401.
package kasa

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	MimeVideo   = "video/x-h264"
	MimeG711U   = "audio/g711u"
	Boundary    = "data-boundary--"
	TimestampHi = "X-Timestamp"
)

// Part is one multipart part: a video access unit or an audio chunk.
type Part struct {
	ContentType string
	Timestamp   time.Duration // X-Timestamp of the part, 0 when absent
	Payload     []byte
}

// Client streams from a Kasa camera over HTTPS.
type Client struct {
	baseURL     string
	username    string
	password    string
	insecureTLS bool
	resp        *http.Response
	rd          *bufio.Reader
}

// NewClient builds a client for the given endpoint.
func NewClient(host, username, password, deviceID, video, audio, resolution string) *Client {
	q := url.Values{}
	q.Set("video", video)
	q.Set("audio", audio)
	q.Set("resolution", resolution)
	if deviceID != "" {
		q.Set("deviceId", deviceID)
	}
	return &Client{
		baseURL:     "https://" + host + "/https/stream/mixed?" + q.Encode(),
		username:    username,
		password:    password,
		insecureTLS: true, // cameras ship a self-signed certificate
	}
}

// Dial opens the HTTPS stream and initialises the reader. The response body
// is kept open until Close is called.
func (c *Client) Dial() error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Connection", "keep-alive")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.insecureTLS,
			// Older Kasa firmware (KD110) aborts the handshake on modern
			// ClientHello content: restrict curves (no post-quantum ML-KEM
			// hybrid, which Go 1.23+ offers by default and breaks legacy
			// servers) and offer widely-supported suites.
			CurvePreferences: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
		// The camera answers with HTTP/1.0 keep-alive semantics; a fresh
		// transport per Dial avoids stale TLS session reuse problems.
	}
	client := &http.Client{Transport: tr} // no global timeout: infinite stream

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("kasa: dial: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		_ = res.Body.Close()
		return &AuthError{Status: res.StatusCode, StatusText: res.Status}
	}

	buf := bufio.NewReader(res.Body)
	b, err := buf.Peek(2)
	if err != nil {
		_ = res.Body.Close()
		return fmt.Errorf("kasa: dial: %w", err)
	}
	// KD110/KC401/KC420WS answer with HTTP/1.0 + chunked. Go strips the
	// transfer-encoding header for HTTP/1.0 responses, so detect the chunked
	// framing from the payload: chunked chunks start with hex digits, while
	// multipart parts start with the boundary "--".
	if !bytes.HasPrefix(b, []byte("--")) {
		buf = bufio.NewReader(httputil.NewChunkedReader(buf))
	}
	c.resp = res
	c.rd = buf
	return nil
}

// AuthError signals an authentication problem during dialling.
type AuthError struct {
	Status     int
	StatusText string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("kasa: dial: %s", e.StatusText)
}

// ReadPart reads the next multipart part.
func (c *Client) ReadPart() (Part, error) {
	if c.rd == nil {
		return Part{}, errors.New("kasa: not dialled")
	}
	header, payload, err := nextPart(c.rd)
	if err != nil {
		return Part{}, err
	}
	p := Part{ContentType: header.Get("Content-Type"), Payload: payload}
	if ts := header.Get(TimestampHi); ts != "" {
		if f, err2 := strconv.ParseFloat(ts, 64); err2 == nil && f > 0 {
			p.Timestamp = time.Duration(f * float64(time.Second))
		}
	}
	return p, nil
}

// RTT returns the TLS/HTTP handshake info of the active connection (logging).
func (c *Client) TLSVersion() string {
	if c.resp == nil || c.resp.TLS == nil {
		return ""
	}
	return c.resp.TLS.NegotiatedProtocol + "|" + c.resp.Proto
}

// Close closes the underlying response body.
func (c *Client) Close() error {
	if c.resp != nil && c.resp.Body != nil {
		return c.resp.Body.Close()
	}
	return nil
}

// nextPart parses one multipart/x-mixed-replace part:
//
//	--data-boundary--\r\n
//	Content-Type: video/x-h264\r\n
//	X-Timestamp: 0.123456\r\n
//	Content-Length: 12345\r\n
//	\r\n
//	<payload>\r\n
func nextPart(r *bufio.Reader) (http.Header, []byte, error) {
	// Skip preamble until the boundary line.
	for {
		line, err := readLine(r)
		if err != nil {
			return nil, nil, err
		}
		if strings.HasPrefix(line, "--"+Boundary) || strings.HasPrefix(line, Boundary) {
			break
		}
	}

	header := http.Header{}
	for {
		line, err := readLine(r)
		if err != nil {
			return nil, nil, err
		}
		if line == "" {
			break
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			header.Add(strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]))
		}
	}
	cl := header.Get("Content-Length")
	if cl == "" {
		return nil, nil, errors.New("kasa: part without Content-Length")
	}
	n, err := strconv.Atoi(cl)
	if err != nil || n < 0 || n > 64<<20 {
		return nil, nil, fmt.Errorf("kasa: invalid Content-Length: %q", cl)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, err
	}
	// trailing CRLF after payload
	if err := skipCRLF(r); err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}

func skipCRLF(r *bufio.Reader) error {
	b1, err := r.ReadByte()
	if err != nil {
		return err
	}
	if b1 != '\r' && b1 != '\n' {
		return errors.New("kasa: missing part terminator")
	}
	if b1 == '\r' {
		b2, err := r.ReadByte()
		if err != nil {
			return err
		}
		if b2 != '\n' {
			return errors.New("kasa: missing part terminator")
		}
	}
	return nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
