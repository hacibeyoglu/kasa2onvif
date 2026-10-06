// Package rtsp - server.go: TCP listener and per-connection session state
// machine (OPTIONS/DESCRIBE/SETUP/PLAY/PAUSE/TEARDOWN), streaming RTP over
// TCP interleaved frames from the hub.
package rtsp

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"kasa2onvif/internal/hub"
)

// Server is the RTSP server.
type Server struct {
	listen string
	hub    *hub.Hub
	auth   *Auth
	path   string        // stream path served, e.g. "/doorcam"
	sdpFn  func() string // dynamic SDP (refreshed per DESCRIBE)
	log    Logger

	mu       sync.Mutex
	sessions map[string]*session
}

// Logger interface.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// NewServer creates a server (call Run to start). sdpFn is called for every
// DESCRIBE so late-joining clients get the real SPS/PPS.
func NewServer(listen string, h *hub.Hub, auth *Auth, path string, sdpFn func() string, log Logger) *Server {
	return &Server{
		listen:   listen,
		hub:      h,
		auth:     auth,
		path:     path,
		sdpFn:    sdpFn,
		log:      log,
		sessions: map[string]*session{},
	}
}

type session struct {
	id         string
	conn       net.Conn
	path       string
	authorized bool
	videoSSRC  uint32
	audioSSRC  uint32
	videoSeq   uint16
	audioSeq   uint16
	videoTS    uint32 // initial RTP timestamp advertised in RTP-Info
	audioTS    uint32
	// start gates the stream goroutine: it waits until the PLAY response
	// (with the matching RTP-Info) has been written, so the first packet on
	// the wire carries exactly the advertised seq/rtptime.
	start     chan struct{}
	startOnce sync.Once
	playing   bool
	stop      chan struct{}
	once      sync.Once
}

// Run starts the listener; blocks until the listener fails.
func (s *Server) Run() error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	s.log.Infof("rtsp: listening on %s", s.listen)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	br := bufio.NewReader(conn)
	var sess *session
	defer func() {
		if sess != nil {
			s.log.Infof("rtsp: session %s from %s ended", sess.id, remote)
			sess.halt()
			s.mu.Lock()
			delete(s.sessions, sess.id)
			s.mu.Unlock()
		}
	}()
	s.log.Infof("rtsp: connection from %s", remote)
	buf := make([]byte, 0, 4096)
	for {
		// read a full RTSP message (headers end with blank line); body length
		// from Content-Length
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return
		}
		headers := map[string]string{}
		total := 0
		for {
			hl, err := br.ReadString('\n')
			if err != nil {
				return
			}
			hl = strings.TrimRight(hl, "\r\n")
			if hl == "" {
				break
			}
			if idx := strings.IndexByte(hl, ':'); idx > 0 {
				headers[strings.ToLower(strings.TrimSpace(hl[:idx]))] = strings.TrimSpace(hl[idx+1:])
			}
		}
		if cl, ok := headers["content-length"]; ok {
			n, _ := strconv.Atoi(cl)
			if n > 0 && n < 65536 {
				body := make([]byte, n)
				if _, err := io.ReadFull(br, body); err != nil {
					return
				}
				total = n
				_ = total
			}
		}
		req := &Message{Method: parts[0], URL: parts[1], Proto: parts[2], Headers: headers}
		sess = s.dispatch(conn, sess, req)
		buf = buf[:0]
	}
}

// dispatch processes one request and writes the response.
func (s *Server) dispatch(conn net.Conn, sess *session, req *Message) *session {
	cseq := req.Header("CSeq")
	resp := Response(req, 200, "OK")
	resp.SetHeader("CSeq", cseq)

	parts := strings.Split(strings.TrimRight(req.URL, "/"), "/")
	reqPath := "/" + parts[len(parts)-1]
	_ = reqPath

	switch req.Method {
	case "OPTIONS":
		resp.SetHeader("Public", "OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER")
	case "DESCRIBE":
		if !s.checkAuth(req, resp) {
			break
		}
		resp.SetHeader("Content-Type", "application/sdp")
		resp.Body = []byte(s.sdpFn())
	case "SETUP":
		if !s.checkAuth(req, resp) {
			break
		}
		if sess == nil {
			sess = &session{
				id:        newSessionID(),
				conn:      conn,
				videoSSRC: 0x5E1F0001,
				audioSSRC: 0x5E1F0002,
				// Both PLAY (RTP-Info) and the stream goroutine use these
				// values, so the advertised seq/rtptime match the first
				// packets exactly.
				videoTS: uint32(time.Since(sessionEpoch).Milliseconds()*90) & 0x7FFFFFFF,
				audioTS: uint32(time.Since(sessionEpoch).Milliseconds()*8) & 0x7FFFFFFF,
				start:   make(chan struct{}),
				stop:    make(chan struct{}),
			}
			s.mu.Lock()
			s.sessions[sess.id] = sess
			s.mu.Unlock()
		}
		transport := req.Header("Transport")
		// only interleaved TCP supported: RTP/AVP/TCP;interleaved=0-1
		if !strings.Contains(transport, "TCP") {
			resp = Response(req, 461, "Unsupported transport")
			resp.SetHeader("CSeq", cseq)
			break
		}
		ch := parseInterleaved(transport)
		if ch < 0 {
			resp = Response(req, 400, "Bad request")
			resp.SetHeader("CSeq", cseq)
			break
		}
		// The SDP advertises trackID=1 (video) and trackID=2 (audio); the
		// interleaved channel must match the track (trackID 1 -> ch 0,
		// trackID 2 -> ch 2).
		_ = ch
		if strings.Contains(transport, "interleaved=0") || ch == 0 || ch == 2 {
			// accepted below
		}
		resp.SetHeader("Session", sess.id+";timeout=65")
		resp.SetHeader("Transport", fmt.Sprintf("RTP/AVP/TCP;interleaved=%d-%d", ch, ch+1))
	case "PLAY":
		if !s.checkAuth(req, resp) {
			break
		}
		if sess == nil {
			resp = Response(req, 454, "Session Not Found")
			resp.SetHeader("CSeq", cseq)
			break
		}
		s.log.Infof("rtsp: session %s PLAY from %s", sess.id, conn.RemoteAddr().String())
		resp.SetHeader("Session", sess.id)
		// RTP-Info must match the sequence/timestamp of the first packets the
		// client will receive (values the stream goroutine will actually use).
		// Earlier versions advertised wall-clock rtptime while the packets
		// carried hub-monotonic timestamps; the mismatch made Protect drop
		// the stream with "no video".
		resp.SetHeader("RTP-Info", fmt.Sprintf("url=%s/trackID=1;seq=%d;rtptime=%d,url=%s/trackID=2;seq=%d;rtptime=%d",
			strings.TrimSuffix(req.URL, "/"), sess.videoSeq, sess.videoTS,
			strings.TrimSuffix(req.URL, "/"), sess.audioSeq, sess.audioTS))
		if !sess.playing {
			sess.playing = true
			go s.stream(sess)
		}
	case "PAUSE":
		if sess != nil {
			sess.halt()
			sess.playing = false
			resp.SetHeader("Session", sess.id)
		}
	case "TEARDOWN":
		if sess != nil {
			sess.halt()
			s.mu.Lock()
			delete(s.sessions, sess.id)
			s.mu.Unlock()
			sess = nil
		}
		resp.SetHeader("Session", "x")
	case "GET_PARAMETER", "SET_PARAMETER":
		// keepalive; accepted without body
	default:
		resp = Response(req, 405, "Method Not Allowed")
		resp.SetHeader("CSeq", cseq)
		resp.SetHeader("Public", "OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN")
	}
	_, _ = conn.Write(resp.Marshal(true))
	// PLAY response is on the wire - release the stream goroutine so the
	// first RTP packet it sends carries exactly the advertised RTP-Info.
	if req.Method == "PLAY" && sess != nil && sess.playing {
		sess.startOnce.Do(func() { close(sess.start) })
	}
	return sess
}

// sessionEpoch is the process start; session RTP timestamps are derived from
// it so RTP-Info values (PLAY response) match the packets exactly.
var sessionEpoch = time.Now()

// checkAuth verifies Authorization; on failure writes 401 to resp.
func (s *Server) checkAuth(req *Message, resp *Message) bool {
	if s.auth == nil {
		return true
	}
	header := req.Header("Authorization")
	if s.auth.Verify(header, req.Method) {
		return true
	}
	resp.Code = 401
	resp.Status = "Unauthorized"
	resp.SetHeader("WWW-Authenticate", s.auth.Challenge())
	return false
}

// stream pumps frames from the hub into interleaved RTP on the connection.
// The first video frame delivered is the hub's latest keyframe (guaranteeing
// SPS/PPS/IDR before any Predictive frame), then the live stream.
func (s *Server) stream(sess *session) {
	// Wait for the PLAY response to be fully written before sending any RTP
	// (guarantees the first packet matches the advertised RTP-Info).
	select {
	case <-sess.start:
	case <-sess.stop:
		return
	}
	sub := s.hub.Subscribe("rtsp-"+sess.id, 512)
	defer s.hub.Remove(sub)
	pkt := NewH264Packetizer()
	writeErr := error(nil)
	// Timestamps must match the RTP-Info advertised in the PLAY response
	// (computed at SETUP time and stored in the session).
	tsVideo := sess.videoTS
	tsAudio := sess.audioTS
	primed := false
	var lastSent []byte
	sendVideo := func(au []byte) {
		// skip exact duplicates (e.g. primed keyframe == first live frame)
		if lastSent != nil && bytesEqual(lastSent, au) {
			return
		}
		lastSent = append(lastSent[:0], au...)
		pkt.Packetize(au, sess.videoSSRC, sess.videoSeq, tsVideo, func(p []byte, marker bool) {
			head := []byte{'$', 0x00, byte(len(p) >> 8), byte(len(p))}
			if _, err := sess.conn.Write(append(head, p...)); err != nil {
				writeErr = err
			}
			sess.videoSeq++
		})
		// advance the RTP timestamp by one frame period (~20fps at 90kHz)
		tsVideo += 4500
	}
	for {
		select {
		case <-sess.stop:
			return
		case f, ok := <-sub.Recv():
			if !ok {
				return
			}
			if f.Dropped {
				continue
			}
			if f.Kind == 0 {
				if !primed {
					// prime with the hub's latest keyframe if the first
					// frame isn't one (covers mid-GOP subscribe races)
					if !f.Keyframe {
						if kf := s.hub.LatestKeyframe(); kf != nil {
							sendVideo(kf)
						}
					}
					primed = true
				}
				sendVideo(f.Payload)
				if writeErr != nil {
					return
				}
			} else if f.Kind == 1 {
				chunk := 160
				for off := 0; off < len(f.Payload); off += chunk {
					c := chunk
					if len(f.Payload)-off < c {
						c = len(f.Payload) - off
					}
					last := off+c >= len(f.Payload)
					p := f.Payload[off : off+c]
					tp := Packet(0, sess.audioSSRC, sess.audioSeq, tsAudio, last, p)
					head := []byte{'$', 0x02, byte(len(tp) >> 8), byte(len(tp))}
					if _, err := sess.conn.Write(append(head, tp...)); err != nil {
						writeErr = err
						return
					}
					sess.audioSeq++
					tsAudio += uint32(c)
				}
			}
		}
	}
}

// parseInterleaved extracts the first channel of "interleaved=0-1".
func parseInterleaved(transport string) int {
	for _, part := range strings.Split(transport, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "interleaved=") {
			val := strings.TrimPrefix(part, "interleaved=")
			a, _, _ := strings.Cut(val, "-")
			n, err := strconv.Atoi(a)
			if err == nil && n%2 == 0 {
				return n
			}
		}
	}
	return -1
}

// halt stops a session's stream goroutine once.
func (sess *session) halt() {
	sess.once.Do(func() { close(sess.stop) })
}

var sessionCounter int
var sessionCounterMu sync.Mutex

func newSessionID() string {
	sessionCounterMu.Lock()
	defer sessionCounterMu.Unlock()
	sessionCounter++
	return fmt.Sprintf("%08X", sessionCounter)
}

// bytesEqual compares two byte slices (len-sensitive).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
