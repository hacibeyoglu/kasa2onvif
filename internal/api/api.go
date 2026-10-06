// Package api implements the admin HTTP API: a JSON status endpoint and an
// index page. (JPEG snapshots would require an H.264 decoder; the RTSP feed
// itself is what UniFi Protect consumes.)
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"kasa2onvif/internal/hub"
)

// ResolutionInfo describes the stream for /api/status.
type ResolutionInfo struct {
	Width  int `json:"width"`
	Height int `json:"height"`
	FPS    int `json:"fps"`
}

// Logger interface.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// StateProvider provides live status information.
type StateProvider interface {
	Status() map[string]any
}

// Server is the API HTTP server.
type Server struct {
	listen string
	hub    *hub.Hub
	res    *ResolutionInfo
	state  StateProvider
	log    Logger
}

// NewServer builds the API server.
func NewServer(listen string, h *hub.Hub, res *ResolutionInfo, state StateProvider, log Logger) *Server {
	return &Server{listen: listen, hub: h, res: res, state: state, log: log}
}

// Handler returns the API HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.status)
	mux.HandleFunc("/", s.index)
	return mux
}

// Run starts the HTTP server (blocks).
func (s *Server) Run() error {
	s.log.Infof("api: listening on %s", s.listen)
	return http.ListenAndServe(s.listen, s.Handler())
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><title>kasa2onvif</title>
<body style="font-family:sans-serif;background:#111;color:#eee;margin:2rem">
<h1>kasa2onvif</h1>
<p>Kasa camera to RTSP + ONVIF proxy.</p>
<ul>
<li><a href="/api/status" style="color:#8cf">/api/status</a> &mdash; status JSON</li>
<li><code>rtsp://this-host:8554/doorcam</code> &mdash; RTSP stream (H.264 + G.711u)</li>
<li>ONVIF device service: <code>http://this-host:8080/onvif/device_service</code></li>
</ul>
</body>`))
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	out := map[string]any{
		"time":        time.Now().Format(time.RFC3339),
		"resolution":  s.res,
		"connections": s.hub.ConsumerCount(),
	}
	if s.state != nil {
		for k, v := range s.state.Status() {
			out[k] = v
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}
