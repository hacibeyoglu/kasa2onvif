package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseYAMLNested(t *testing.T) {
	doc := `
# comment
rtsp:
  listen: ":8554"   # inline comment
  paths:
    - "doorcam"
    - sub
  enabled: true
onvif:
  name: "Kasa 'Door' bell"
`
	m, err := ParseYAML(doc)
	if err != nil {
		t.Fatal(err)
	}
	rtsp, ok := m["rtsp"].(map[string]any)
	if !ok {
		t.Fatalf("rtsp not a map: %T", m["rtsp"])
	}
	if rtsp["listen"] != ":8554" {
		t.Errorf("listen = %v", rtsp["listen"])
	}
	paths, ok := rtsp["paths"].([]string)
	if !ok || len(paths) != 2 || paths[0] != "doorcam" || paths[1] != "sub" {
		t.Errorf("paths = %v", rtsp["paths"])
	}
	if rtsp["enabled"] != "true" {
		t.Errorf("enabled = %v", rtsp["enabled"])
	}
	onvif := m["onvif"].(map[string]any)
	if onvif["name"] != "Kasa 'Door' bell" {
		t.Errorf("name = %v", onvif["name"])
	}
}

func TestLoadFullConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
source:
  kasa: "kasa://hacibeyoglu%40gmail.com:Kasa.1234@kd110:19443/https/stream/mixed?video=h264&audio=g711&resolution=hd"
rtsp:
  listen: ":8554"
  username: "u1"
  password: "p1"
  paths:
    - "doorcam"
onvif:
  username: "onvif"
  password: "secret"
  name: "Door"
  model: "KD110"
discovery:
  enabled: "true"
api:
  listen: ":8080"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source.Host != "kd110:19443" {
		t.Errorf("host = %q", cfg.Source.Host)
	}
	if cfg.Source.Username != "hacibeyoglu@gmail.com" {
		t.Errorf("username = %q", cfg.Source.Username)
	}
	if cfg.Source.Password != "Kasa.1234" {
		t.Errorf("password = %q", cfg.Source.Password)
	}
	if cfg.Source.Resolution != "hd" || cfg.Source.Video != "h264" || cfg.Source.Audio != "g711" {
		t.Errorf("source defaults wrong: %+v", cfg.Source)
	}
	if cfg.RTSP.Username != "u1" || cfg.RTSP.Password != "p1" {
		t.Errorf("rtsp = %+v", cfg.RTSP)
	}
	if len(cfg.RTSP.Paths) != 1 || cfg.RTSP.Paths[0] != "doorcam" {
		t.Errorf("paths = %v", cfg.RTSP.Paths)
	}
	if cfg.Onvif.Username != "onvif" || cfg.Onvif.Password != "secret" {
		t.Errorf("onvif = %+v", cfg.Onvif)
	}
	if !cfg.Discovery.Enabled {
		t.Error("discovery should be enabled")
	}
}
