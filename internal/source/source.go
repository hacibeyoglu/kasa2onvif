// Package source manages the upstream connection to the Kasa camera: dial
// (with a credential ladder), reconnect with backoff, parse multipart parts
// into frames and feed the hub.
package source

import (
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"kasa2onvif/internal/config"
	"kasa2onvif/internal/core"
	"kasa2onvif/internal/h264"
	"kasa2onvif/internal/hub"
	"kasa2onvif/internal/kasa"
)

// Logger is the logging interface used by the source.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Source pulls frames from the camera into the hub.
type Source struct {
	cfg *config.Source
	hub *hub.Hub
	log Logger

	mu    sync.Mutex
	state string
}

// New builds a source.
func New(cfg *config.Source, h *hub.Hub, log Logger) *Source {
	return &Source{cfg: cfg, hub: h, log: log}
}

// State returns a human-readable state.
func (s *Source) State() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Run blocks, managing reconnects, until stop is closed.
func (s *Source) Run(stop <-chan struct{}) {
	backoff := 2 * time.Second
	for {
		select {
		case <-stop:
			return
		default:
		}
		err := s.runOnce(stop)
		if err == nil {
			s.log.Infof("kasa: stopped")
			return
		}
		s.log.Warnf("kasa: session ended: %v", err)
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		s.log.Infof("kasa: reconnecting in %s", backoff)
		select {
		case <-stop:
			return
		case <-time.After(backoff):
			backoff = 2 * time.Second
		}
	}
}

// runOnce runs one connected session until an error occurs or stop closes.
func (s *Source) runOnce(stop <-chan struct{}) error {
	// Credential ladder: per the reverse-engineering notes the protocol
	// authenticates with (url-safe e-mail, base64(password)); some firmware
	// variants accept the raw pair or the username "admin".
	variants := credentialVariants(s.cfg.Username, s.cfg.Password)
	var client *kasa.Client
	var lastErr error
	for _, v := range variants {
		c := kasa.NewClient(s.cfg.Host, v.user, v.pass, s.cfg.DeviceID, s.cfg.Video, s.cfg.Audio, s.cfg.Resolution)
		err := c.Dial()
		if err == nil {
			s.log.Infof("kasa: connected to %s (auth=%s)", s.cfg.Host, v.note)
			client = c
			break
		}
		_ = c.Close()
		lastErr = err
		if ae, ok := err.(*kasa.AuthError); ok {
			s.log.Warnf("kasa: auth rejected (%s) with %s", ae.StatusText, v.note)
			continue
		}
		return fmt.Errorf("kasa: dial: %w", err)
	}
	if client == nil {
		return fmt.Errorf("kasa: dial: %w (all credentials rejected)", lastErr)
	}
	defer client.Close()

	s.mu.Lock()
	s.state = "connected"
	s.mu.Unlock()

	return s.pump(client, stop)
}

// pump reads parts and publishes frames. Timestamps are rebuilt on the proxy:
// the camera X-Timestamps are wall-clock based and can jump (and reset after
// a camera reboot), which is what makes consumers freeze; RTP timestamps are
// therefore derived from the local monotonic clock, with the camera
// timestamp used only for large-drift detection and rebasing.
func (s *Source) pump(client *kasa.Client, stop <-chan struct{}) error {
	var videoBase, audioBase int64 = -1, -1
	localBase := time.Now()

	// mapTs maps a camera timestamp (ms) to the proxy local timeline.
	mapTs := func(kind uint8, cameraMilli int64) time.Duration {
		now := time.Now()
		localMs := now.Sub(localBase).Milliseconds()
		if kind == 0 {
			if videoBase < 0 {
				videoBase = cameraMilli
				localBase = now
				return 0
			}
			if cameraMilli > 0 {
				// delta between camera pace and local pace
				delta := cameraMilli - (videoBase + localMs)
				if delta > 500 {
					// camera clock is ahead; stretch the local base
					localBase = localBase.Add(time.Duration(delta-100) * time.Millisecond)
				} else if delta < -1500 {
					s.log.Warnf("kasa: camera timestamp jumped backwards, rebasing timeline")
					videoBase = cameraMilli
					localBase = now
					return 0
				}
			}
		} else {
			if audioBase < 0 && cameraMilli > 0 {
				audioBase = cameraMilli
			}
		}
		return time.Duration(now.Sub(localBase).Milliseconds()) * time.Millisecond
	}

	frames := 0
	lastReport := time.Now()
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		part, err := client.ReadPart()
		if err != nil {
			return fmt.Errorf("kasa: read: %w", err)
		}
		switch part.ContentType {
		case kasa.MimeVideo:
			key := false
			for _, n := range h264.SplitAccessUnit(part.Payload) {
				if n.Type == 5 || n.Type == 7 {
					key = true
					break
				}
				if n.Type == 8 {
					key = true
				}
			}
			ts := mapTs(0, part.Timestamp.Milliseconds())
			s.hub.Publish(&core.Frame{Kind: 0, Payload: part.Payload, Timestamp: ts, Keyframe: key})
			frames++
		case kasa.MimeG711U:
			ts := mapTs(1, part.Timestamp.Milliseconds())
			s.hub.Publish(&core.Frame{Kind: 1, Payload: part.Payload, Timestamp: ts})
		default:
			s.log.Warnf("kasa: unknown part content type: %q", part.ContentType)
		}
		if now := time.Now(); now.Sub(lastReport) > 30*time.Second {
			s.log.Infof("kasa: %d parts in the last 30s", frames)
			frames = 0
			lastReport = now
		}
	}
}

type credVariant struct{ user, pass, note string }

// credentialVariants lists the Basic-auth variants to try, in order.
func credentialVariants(user, pass string) []credVariant {
	encoded := base64.StdEncoding.EncodeToString([]byte(pass))
	return []credVariant{
		{user: user, pass: encoded, note: "email+base64(password)"},
		{user: user, pass: pass, note: "email+plain"},
		{user: "admin", pass: encoded, note: "admin+base64(password)"},
		{user: "admin", pass: pass, note: "admin+plain"},
	}
}
