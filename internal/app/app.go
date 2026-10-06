// Package app wires all components together and holds shared state
// (SPS/PPS stream info used for the RTSP SDP).
package app

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"kasa2onvif/internal/api"
	"kasa2onvif/internal/config"
	"kasa2onvif/internal/h264"
	"kasa2onvif/internal/hub"
	"kasa2onvif/internal/onvif"
	"kasa2onvif/internal/rtsp"
	"kasa2onvif/internal/source"
)

// Version is reported in status and logs.
const Version = "1.0.0"

// Logger is the shared minimal logger interface.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// StreamInfo carries the discovered SPS/PPS + framerate of the live stream.
type StreamInfo struct {
	mu        sync.Mutex
	sps       []byte
	pps       []byte
	profile   string
	width     int
	height    int
	fps       float64
	lastVideo time.Time
}

// Set updates the SPS/PPS from an Annex-B access unit.
func (si *StreamInfo) Set(accessUnit []byte) {
	updated := false
	for _, n := range h264.SplitAccessUnit(accessUnit) {
		switch n.Type {
		case 7:
			si.mu.Lock()
			si.sps = append([]byte(nil), n.Bytes...)
			si.mu.Unlock()
		case 8:
			si.mu.Lock()
			si.pps = append([]byte(nil), n.Bytes...)
			si.mu.Unlock()
		}
	}
	sps, _, ok := si.SPSPPS()
	if ok {
		if parsed, err := h264.ParseSPS(sps); err == nil {
			si.mu.Lock()
			si.width = parsed.Width
			si.height = parsed.Height
			si.profile = h264.ProfileName(parsed.ProfileIDC)
			if parsed.FPS > 0 && si.fps == 0 {
				si.fps = parsed.FPS
			}
			si.mu.Unlock()
			updated = true
		}
	}
	_ = updated
}

// SPSPPS returns the current SPS and PPS (without start codes).
func (si *StreamInfo) SPSPPS() ([]byte, []byte, bool) {
	si.mu.Lock()
	defer si.mu.Unlock()
	if si.sps == nil || si.pps == nil {
		return nil, nil, false
	}
	return si.sps, si.pps, true
}

// MarkVideo updates the last-video timestamp.
func (si *StreamInfo) MarkVideo() {
	si.mu.Lock()
	si.lastVideo = time.Now()
	si.mu.Unlock()
}

// Dimensions returns width/height (0 when unknown).
func (si *StreamInfo) Dimensions() (int, int) {
	si.mu.Lock()
	defer si.mu.Unlock()
	return si.width, si.height
}

// Stats snapshots the stream info.
func (si *StreamInfo) Stats() map[string]any {
	si.mu.Lock()
	defer si.mu.Unlock()
	out := map[string]any{
		"width":   si.width,
		"height":  si.height,
		"profile": si.profile,
	}
	if si.fps > 0 {
		out["fps"] = int(si.fps + 0.5)
	}
	if !si.lastVideo.IsZero() {
		out["last_video_ago_ms"] = time.Since(si.lastVideo).Milliseconds()
	}
	return out
}

// App is the running application.
type App struct {
	cfg  *config.Config
	log  Logger
	hub  *hub.Hub
	info *StreamInfo
	src  *source.Source
	srv  *rtsp.Server
	stop chan struct{}
}

// New builds the app.
func New(cfg *config.Config, log Logger) *App {
	return &App{
		cfg:  cfg,
		log:  log,
		hub:  hub.New(),
		info: &StreamInfo{},
		stop: make(chan struct{}),
	}
}

// sdp builds the SDP from live stream info (falls back to placeholders).
func (a *App) sdp() string {
	sprop := ""
	profileID := ""
	if sps, pps, ok := a.info.SPSPPS(); ok {
		prof := ""
		if len(sps) >= 4 {
			prof = fmt.Sprintf("%02X%02X%02X", sps[1], sps[2], sps[3])
		}
		profileID = ";profile-level-id=" + prof
		sprop = ";sprop-parameter-sets=" +
			base64.StdEncoding.EncodeToString(sps) + "," +
			base64.StdEncoding.EncodeToString(pps)
	}
	return "v=0\r\n" +
		"o=- " + strconv.FormatInt(time.Now().Unix(), 10) + " 1 IN IP4 0.0.0.0\r\n" +
		"s=" + a.cfg.Onvif.Name + "\r\n" +
		"i=kasa2onvif " + Version + "\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"t=0 0\r\n" +
		"m=video 0 RTP/AVP 96\r\n" +
		"a=rtpmap:96 H264/90000\r\n" +
		"a=fmtp:96 packetization-mode=1" + profileID + sprop + "\r\n" +
		"a=control:trackID=1\r\n" +
		"m=audio 0 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=control:trackID=2\r\n"
}

// Start launches all components.
func (a *App) Start() error {
	if len(a.cfg.RTSP.Paths) == 0 {
		a.cfg.RTSP.Paths = []string{"doorcam"}
	}
	path := "/" + strings.Trim(a.cfg.RTSP.Paths[0], "/")

	a.src = source.New(a.cfg.Source, a.hub, a.log)
	auth := rtsp.NewAuth(a.cfg.RTSP.Username, a.cfg.RTSP.Password, a.cfg.RTSP.Realm)
	// Protect retries the ONVIF/adoption credentials on the RTSP URI - accept
	// those too, or the adopted camera shows "no video".
	auth.AddCredentials(a.cfg.Onvif.Username, a.cfg.Onvif.Password)
	a.srv = rtsp.NewServer(a.cfg.RTSP.Listen, a.hub, auth, path, a.sdp, a.log)

	onvifAuth := onvif.NewAuth(a.cfg.Onvif.Username, a.cfg.Onvif.Password)
	ip := a.cfg.Onvif.RTSPHost
	if ip == "" {
		ip = onvif.JustifyIP(a.cfg.NetworkInterface)
	}
	port := a.cfg.Onvif.RTSPPort
	if port == 0 {
		if _, p, err := splitHostPort(a.cfg.RTSP.Listen); err == nil && p != 0 {
			port = p
		} else {
			port = 8554
		}
	}
	rtspURL := fmt.Sprintf("rtsp://%s:%d%s", ip, port, path)
	apiPort := httpPort(a.cfg.API.Listen)
	// Advertised service address (IP:port of the ONVIF/API listener). Used
	// for XAddrs in GetCapabilities/GetServices and discovery; must never be
	// empty - Protect builds request URLs from it.
	xaddrIP := orStr(a.cfg.Onvif.DeviceXAddr, ip+":"+apiPort)

	w, h := a.info.Dimensions()
	// Trust explicit config values, else the live SPS parse when plausible,
	// else the known KD110 hd output (1280x720).
	mw, mh := a.cfg.Onvif.Width, a.cfg.Onvif.Height
	if mw == 0 || mh == 0 {
		mw, mh = fallbackInt(w, 1280), fallbackInt(h, 720)
	}
	media := &onvif.MediaInfo{
		ProfileToken: "PROFILE_000",
		ProfileName:  a.cfg.Onvif.ProfileName,
		Width:        mw,
		Height:       mh,
		FPS:          20,
		Encoder:      "H264",
		BitrateLimit: 4096,
		GOVLength:    60,
		RTSPURL:      rtspURL,
		SnapshotURI:  "http://" + ip + ":" + apiPort + "/api/status",
		AudioEncoder: "G711",
		// The Kasa multiplexed stream carries G.711u audio in lockstep; expose
		// it in the ONVIF profile or Protect shows the camera muted.
		HasAudio: true,
	}
	// width/height refresh: Protect reads these once during adoption; the
	// watcher goroutine patches the service via the closure below.
	// NOTE: IPAddress is the advert address (ip:apiPort) used to build XAddrs
	// in GetCapabilities/GetServices - an empty value makes Protect build
	// requests like "/http://" which fail with 301 during adoption.
	svc := onvif.NewService(&onvif.DeviceInfo{
		Manufacturer: a.cfg.Onvif.Manufacturer,
		Model:        a.cfg.Onvif.Model,
		Firmware:     a.cfg.Onvif.Firmware,
		Serial:       a.cfg.Onvif.Serial,
		Name:         a.cfg.Onvif.Name,
		HardwareID:   orStr(a.cfg.Onvif.HardwareID, a.cfg.Onvif.Model),
		MAC:          a.cfg.Onvif.MAC,
		IPAddress:    xaddrIP, // ip:apiPort (or configured device_xaddr)
	}, media, onvifAuth)

	xaddr := xaddrIP
	disc := onvif.NewDiscovery("", xaddr, scopesLine(a.cfg.Onvif))

	// Combined HTTP listener: /api/* + index from api, /onvif/device_service
	// (and other /onvif/* paths) from the ONVIF service.
	apiState := &appState{app: a}
	apiSrv := api.NewServer(a.cfg.API.Listen, a.hub, &api.ResolutionInfo{
		Width:  media.Width,
		Height: media.Height,
		FPS:    media.FPS,
	}, apiState, a.log)
	// Let the ONVIF service pick up live dimensions once the SPS arrives,
	// honouring explicit config over parsed values.
	go func() {
		for {
			select {
			case <-a.stop:
				return
			case <-time.After(5 * time.Second):
				lw, lh := a.info.Dimensions()
				if lw > 0 && lh > 0 && (media.Width != lw || media.Height != lh) && a.cfg.Onvif.Width == 0 {
					media.Width, media.Height = lw, lh
				}
			}
		}
	}()
	handler := http.NewServeMux()
	handler.Handle("/onvif", svc)
	handler.Handle("/onvif/", svc)
	handler.Handle("/api/", apiSrv.Handler())
	// UniFi Protect POSTs SOAP directly to the media XAddr root ("/")-
	// those requests must reach the ONVIF service, not the HTML index.
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			svc.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" {
			apiSrv.Handler().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	_ = apiSrv // apiSrv.Handler used; Run not used (combined server below)

	// watcher: update SPS/PPS info from the hub (also keeps stream fresh)
	go a.watchStream()

	go func() {
		a.log.Infof("http: listening on %s (api + onvif device service)", a.cfg.API.Listen)
		if err := http.ListenAndServe(a.cfg.API.Listen, handler); err != nil {
			a.log.Errorf("http: %v", err)
		}
	}()
	go func() {
		if err := a.srv.Run(); err != nil {
			a.log.Errorf("rtsp: %v", err)
		}
	}()
	if a.cfg.Discovery.Enabled {
		go func() {
			if err := disc.Run(a.stop); err != nil {
				a.log.Warnf("discovery: %v", err)
			}
		}()
	}
	go a.src.Run(a.stop)

	a.log.Infof("app: kasa2onvif %s started (rtsp=%s path=%s onvif=http://%s/onvif/device_service discovery=%v)",
		Version, a.cfg.RTSP.Listen, path, xaddr, a.cfg.Discovery.Enabled)
	return nil
}

// Stop terminates all components.
func (a *App) Stop() {
	select {
	case <-a.stop:
	default:
		close(a.stop)
	}
}

// Wait blocks until SIGINT/SIGTERM.
func (a *App) Wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	a.log.Infof("app: shutting down")
	a.Stop()
}

// watchStream subscribes to the hub and updates SPS/PPS info.
func (a *App) watchStream() {
	sub := a.hub.Subscribe("watcher", 16)
	defer a.hub.Remove(sub)
	for f := range sub.Recv() {
		if f.Kind == 0 {
			a.info.Set(f.Payload)
			a.info.MarkVideo()
		}
	}
}

// statusMap implements part of api.StateProvider.
func (a *App) statusMap() map[string]any {
	return map[string]any{
		"version": Version,
		"source":  a.cfg.Source.Raw,
	}
}

type appState struct{ app *App }

func (s *appState) Status() map[string]any {
	m := s.app.statusMap()
	for k, v := range s.app.info.Stats() {
		m[k] = v
	}
	return m
}

// helpers

func splitHostPort(s string) (string, int, error) {
	last := strings.LastIndexByte(s, ':')
	if last < 0 {
		return s, 0, fmt.Errorf("missing port")
	}
	port, err := strconv.Atoi(s[last+1:])
	if err != nil {
		return s, 0, err
	}
	return s[:last], port, nil
}

func httpPort(listen string) string {
	_, p, err := splitHostPort(listen)
	if err != nil || p == 0 {
		return "8080"
	}
	return strconv.Itoa(p)
}

func orStr(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func fallbackInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func scopesLine(c *config.OnvifConfig) string {
	mac := strings.ReplaceAll(strings.ToUpper(c.MAC), ":", "")
	return "onvif://www.onvif.org/Profile/Streaming" +
		" onvif://www.onvif.org/Name/" + c.Name +
		" onvif://www.onvif.org/Model/" + c.Model +
		" onvif://www.onvif.org/MAC/" + mac
}
