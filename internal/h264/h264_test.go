package h264

import (
	"bytes"
	"testing"
)

// spsBaseline is a real x264 SPS for 640x480 baseline @ level 2.2.
var spsBaseline = []byte{
	0x67, 0x42, 0xC0, 0x16, 0xD9, 0x00, 0xA0, 0x3D, 0xB0, 0x11, 0x00, 0x00, 0x03,
	0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x14, 0x0F, 0x16, 0x2E, 0x48,
}

func TestSplitAccessUnit(t *testing.T) {
	au := []byte{
		0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E, // SPS
		0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80, // PPS
		0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21, 0xA0, // IDR
	}
	nals := SplitAccessUnit(au)
	if len(nals) != 3 {
		t.Fatalf("got %d NALUs, want 3", len(nals))
	}
	if nals[0].Type != 7 || nals[1].Type != 8 || nals[2].Type != 5 {
		t.Errorf("types = %d %d %d", nals[0].Type, nals[1].Type, nals[2].Type)
	}
	if !bytes.Equal(nals[2].Bytes, []byte{0x65, 0x88, 0x84, 0x21, 0xA0}) {
		t.Errorf("IDR bytes = %x", nals[2].Bytes)
	}
}

func TestFindNALU(t *testing.T) {
	au := []byte{
		0x00, 0x00, 0x01, 0x67, 0x42,
		0x00, 0x00, 0x00, 0x01, 0x68, 0xCE,
		0x00, 0x00, 0x01, 0x61, 0x33,
	}
	if got := len(FindNALU(au, 7)); got != 1 {
		t.Errorf("SPS count = %d", got)
	}
	if got := len(FindNALU(au, 1)); got != 1 {
		t.Errorf("slice count = %d", got)
	}
}

func TestParseSPSBaseline(t *testing.T) {
	sps, err := ParseSPS(spsBaseline)
	if err != nil {
		t.Fatal(err)
	}
	if sps.ProfileIDC != 66 {
		t.Errorf("profile = %d", sps.ProfileIDC)
	}
	if sps.LevelIDC != 22 {
		t.Errorf("level = %d", sps.LevelIDC)
	}
	if sps.Width != 640 || sps.Height != 480 {
		t.Errorf("dims = %dx%d", sps.Width, sps.Height)
	}
}

func TestProfileName(t *testing.T) {
	if ProfileName(66) != "Baseline" || ProfileName(77) != "Main" {
		t.Error("bad profile names")
	}
}
