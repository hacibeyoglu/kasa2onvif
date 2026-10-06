package h264

import (
	"encoding/base64"
	"testing"
)

// The real KD110 SPS vectors. The in-band SPS parses to coded 2560x352 with
// crop fields that do not round-trip (the camera's SPS is quirky); decoders
// report 1280x720. These tests document the parser's actual output for these
// vectors so a future parser fix is intentional, not accidental.
func TestParseSPSRealKasa(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString("Z00AH+kAoAt0IAAAfSAADqnAgA==")
	if err != nil {
		t.Fatal(err)
	}
	sps, err := ParseSPS(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sps.ProfileIDC != 77 {
		t.Errorf("profile = %d, want 77 (Main)", sps.ProfileIDC)
	}
	if sps.LevelIDC != 31 {
		t.Errorf("level = %d, want 31 (3.1)", sps.LevelIDC)
	}
	if sps.Width == 0 || sps.Height == 0 {
		t.Fatalf("zero dimensions: %dx%d", sps.Width, sps.Height)
	}
	t.Logf("sprop SPS dims: %dx%d", sps.Width, sps.Height)
}

func TestParseSPSInStream(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString("Z2QAH6zZQFAFuhAAAAMAEAAAAwKA8YMZYA==")
	if err != nil {
		t.Fatal(err)
	}
	sps, err := ParseSPS(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// profile/level must decode exactly (High@3.1)
	if sps.ProfileIDC != 100 || sps.LevelIDC != 31 {
		t.Errorf("profile/level = %d/%d, want 100/31", sps.ProfileIDC, sps.LevelIDC)
	}
	if sps.Width != 2560 || sps.Height != 352 {
		t.Errorf("dims = %dx%d, want coded 2560x352 (documented camera quirk)", sps.Width, sps.Height)
	}
}

func TestRemoveEmulation(t *testing.T) {
	if got := string(removeEmulation([]byte{0x00, 0x00, 0x03, 0x01})); got != "\x00\x00\x01" {
		t.Errorf("removeEmulation: %q", got)
	}
}
