// Package config loads kasa2onvif configuration from YAML.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Source is the Kasa camera connection settings.
type Source struct {
	Raw        string
	Host       string
	Username   string
	Password   string
	DeviceID   string
	Video      string
	Audio      string
	Resolution string
}

// RTSPConfig configures the internal RTSP server.
type RTSPConfig struct {
	Listen   string
	Username string
	Password string
	Realm    string
	Paths    []string
}

// OnvifConfig configures the ONVIF device/media service.
type OnvifConfig struct {
	DeviceXAddr  string
	Username     string
	Password     string
	Name         string
	Manufacturer string
	Model        string
	Firmware     string
	Serial       string
	MAC          string
	HardwareID   string
	ProfileName  string
	// Stream dimensions reported via ONVIF; when 0 they default to the
	// actual KD110 hd-formatted output (1280x720, see README).
	Width    int
	Height   int
	RTSPPort int
	RTSPHost string
}

// DiscoveryConfig configures WS-Discovery.
type DiscoveryConfig struct {
	Enabled bool
	Listen  string
}

// APIConfig configures the admin HTTP API.
type APIConfig struct {
	Listen string
}

// LogConfig configures logging.
type LogConfig struct {
	Level        string
	StatsSeconds int
}

// Config is the whole configuration file.
type Config struct {
	NetworkInterface string
	Source           *Source
	RTSP             *RTSPConfig
	Onvif            *OnvifConfig
	Discovery        *DiscoveryConfig
	API              *APIConfig
	Log              *LogConfig
}

// Load reads and parses the configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := ParseYAML(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}

	cfg := &Config{
		Source:    &Source{},
		RTSP:      &RTSPConfig{},
		Onvif:     &OnvifConfig{},
		Discovery: &DiscoveryConfig{},
		API:       &APIConfig{},
		Log:       &LogConfig{},
	}
	str := func(v any, def string) string {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
		return def
	}

	if v, ok := doc["network_interface"].(map[string]any); ok {
		cfg.NetworkInterface = str(v["name"], "")
	}
	if v, ok := doc["source"].(map[string]any); ok {
		src := str(v["kasa"], "")
		if src != "" {
			if err := parseSource(cfg.Source, src); err != nil {
				return nil, err
			}
		}
	}
	if v, ok := doc["rtsp"].(map[string]any); ok {
		cfg.RTSP.Listen = str(v["listen"], ":8554")
		cfg.RTSP.Username = str(v["username"], "kasa2onvif")
		cfg.RTSP.Password = str(v["password"], "")
		cfg.RTSP.Realm = str(v["realm"], "kasa2onvif")
		if items, ok := v["paths"].([]string); ok && len(items) > 0 {
			cfg.RTSP.Paths = items
		}
	}
	if v, ok := doc["onvif"].(map[string]any); ok {
		cfg.Onvif.DeviceXAddr = str(v["device_xaddr"], "")
		cfg.Onvif.Username = str(v["username"], "onvif")
		cfg.Onvif.Password = str(v["password"], "")
		cfg.Onvif.Name = str(v["name"], "Kasa Doorbell")
		cfg.Onvif.Manufacturer = str(v["manu"+"facturer"], "TP-Link")
		cfg.Onvif.Model = str(v["model"], "KD110")
		cfg.Onvif.Firmware = str(v["firmware"], "1.0.0")
		cfg.Onvif.Serial = str(v["serial"], "")
		cfg.Onvif.MAC = str(v["mac"], "")
		cfg.Onvif.HardwareID = str(v["hardware"], "")
		cfg.Onvif.ProfileName = str(v["profile"], "PROFILE_000")
		if wp := str(v["width"], ""); wp != "" {
			n, err := strconv.Atoi(wp)
			if err != nil {
				return nil, fmt.Errorf("onvif: invalid width: %q", wp)
			}
			cfg.Onvif.Width = n
		}
		if hp := str(v["height"], ""); hp != "" {
			n, err := strconv.Atoi(hp)
			if err != nil {
				return nil, fmt.Errorf("onvif: invalid height: %q", hp)
			}
			cfg.Onvif.Height = n
		}
		cfg.Onvif.RTSPHost = str(v["rtsp_host"], "")
		if p := str(v["rtsp_port"], ""); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, fmt.Errorf("onvif: invalid rtsp_port: %q", p)
			}
			cfg.Onvif.RTSPPort = n
		}
	}
	if v, ok := doc["discovery"].(map[string]any); ok {
		cfg.Discovery.Listen = str(v["listen"], ":3702")
		enabled := str(v["enabled"], "true")
		cfg.Discovery.Enabled = enabled == "true" || enabled == "1" || enabled == "yes"
	}
	if v, ok := doc["api"].(map[string]any); ok {
		cfg.API.Listen = str(v["listen"], ":8080")
	}
	if v, ok := doc["log"].(map[string]any); ok {
		cfg.Log.Level = str(v["level"], "info")
		if s := str(v["stats"], ""); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				return nil, fmt.Errorf("log: invalid stats interval: %q", s)
			}
			cfg.Log.StatsSeconds = n
		}
	}
	return cfg, nil
}

// parseSource parses a kasa:// source URL.
func parseSource(s *Source, raw string) error {
	if !strings.HasPrefix(raw, "kasa://") {
		return fmt.Errorf("source: unsupported scheme (expected kasa://): %s", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.User == nil {
		return fmt.Errorf("source: kasa URL requires user:password@host")
	}
	s.Raw = raw
	s.Host = u.Host
	s.Username = u.User.Username()
	s.Password, _ = u.User.Password()
	if s.Username == "" {
		s.Username = "admin"
	}
	q := u.Query()
	s.DeviceID = q.Get("deviceId")
	s.Video = or(q.Get("video"), "h264")
	s.Audio = or(q.Get("audio"), "g711")
	s.Resolution = or(q.Get("resolution"), "hd")
	return nil
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
