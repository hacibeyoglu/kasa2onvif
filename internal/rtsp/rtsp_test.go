package rtsp

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestPacketHeader(t *testing.T) {
	pkt := Packet(96, 0x11223344, 0x4242, 90000, true, []byte{1, 2, 3})
	if pkt[0] != 0x80 {
		t.Errorf("version/flags = %x", pkt[0])
	}
	if pkt[1] != 0x80|96 { // marker + PT
		t.Errorf("pt/marker = %x", pkt[1])
	}
	if binary.BigEndian.Uint16(pkt[2:4]) != 0x4242 {
		t.Errorf("seq = %x", pkt[2:4])
	}
	if binary.BigEndian.Uint32(pkt[4:8]) != 90000 {
		t.Errorf("ts = %x", pkt[4:8])
	}
	if binary.BigEndian.Uint32(pkt[8:12]) != 0x11223344 {
		t.Errorf("ssrc = %x", pkt[8:12])
	}
	if len(pkt) != 15 {
		t.Errorf("len = %d", len(pkt))
	}
}

// pattern returns n bytes of deterministic non-zero data (all-zero payloads
// would be trimmed by the NAL splitter as start-code padding).
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(0x10 + i%0x40)
	}
	return b
}

// IDR frame: SPS + PPS + big slice, verifying STAP-A aggregation and FU-A
// fragmentation.
func TestH264PacketizeIDR(t *testing.T) {
	sps := append([]byte{0x67}, pattern(10)...)     // type 7
	pps := append([]byte{0x68}, pattern(4)...)      // type 8
	slice := append([]byte{0x65}, pattern(3000)...) // type 5, big -> FU-A
	au := joinAnnexB(sps, pps, slice)

	p := &H264Packetizer{MaxPayload: 1400}
	var types []byte
	var markers []bool
	p.Packetize(au, 1, 0, 1000, func(pkt []byte, marker bool) {
		types = append(types, pkt[12]&0x1F) // NAL type = first payload byte
		markers = append(markers, marker)
	})
	// Expect: STAP-A (SPS+PPS) then ceil(3000/1398)=3 FU-A fragments
	if len(types) != 4 {
		t.Fatalf("packets = %d (%v), want 4", len(types), types)
	}
	if types[0] != 24 {
		t.Errorf("first packet type = %d, want 24 (STAP-A)", types[0])
	}
	for i, tp := range types[1:] {
		if tp != 28 {
			t.Errorf("fragment %d type = %d, want 28 (FU-A)", i+1, tp)
		}
	}
	if markers[0] {
		t.Error("STAP-A must not have marker")
	}
	if !markers[len(markers)-1] {
		t.Error("last FU-A fragment must have marker")
	}
}

func TestH264PacketizeSmallPFrame(t *testing.T) {
	slice := append([]byte{0x41}, pattern(100)...) // type 1, small
	au := joinAnnexB(slice)
	p := &H264Packetizer{MaxPayload: 1400}
	packets := 0
	p.Packetize(au, 1, 0, 1000, func(pkt []byte, marker bool) {
		packets++
		if got := pkt[12] & 0x1F; got != 1 {
			t.Errorf("type = %d, want 1", got)
		}
		if !marker {
			t.Error("single NAL packet should carry the AU marker")
		}
	})
	if packets != 1 {
		t.Errorf("packets = %d", packets)
	}
}

func TestH264PacketizeFragmentsContinueSeq(t *testing.T) {
	slice := append([]byte{0x65}, pattern(4000)...)
	au := joinAnnexB(slice)
	p := &H264Packetizer{MaxPayload: 1400}
	var seq uint16 = 100
	var out [][]byte
	p.Packetize(au, 1, seq, 1000, func(pkt []byte, marker bool) {
		out = append(out, pkt)
		seq++ // the caller owns the sequence
	})
	if seq != 100+uint16(len(out)) {
		t.Errorf("final seq = %d, want %d", seq, 100+len(out))
	}
	first, last := out[0], out[len(out)-1]
	if first[12]&0x1F != 28 {
		t.Errorf("FU indicator type = %d, want 28", first[12]&0x1F)
	}
	if first[12]&0x60 == 0 {
		t.Error("FU indicator lost NRI bits")
	}
	if first[13]&0x80 == 0 {
		t.Error("first FU-A fragment missing S bit")
	}
	if last[13]&0x40 == 0 {
		t.Error("last FU-A fragment missing E bit")
	}
}

func TestParseInterleaved(t *testing.T) {
	if n := parseInterleaved("RTP/AVP/TCP;interleaved=0-1"); n != 0 {
		t.Errorf("got %d", n)
	}
	if n := parseInterleaved("RTP/AVP/TCP;unicast;interleaved=2-3"); n != 2 {
		t.Errorf("got %d", n)
	}
	if n := parseInterleaved("RTP/AVP/UDP;unicast=0-1"); n != -1 {
		t.Errorf("got %d", n)
	}
}

func TestG711Packetize(t *testing.T) {
	payload := pattern(400) // 40ms at 8kHz -> chunks of 160,160,80
	wantLen := []int{12 + 160, 12 + 160, 12 + 80}
	i := 0
	seq := G711Packetize(payload, 7, 0, 0, 160, func(pkt []byte, marker bool) {
		if len(pkt) != wantLen[i] {
			t.Errorf("packet %d len = %d, want %d", i, len(pkt), wantLen[i])
		}
		if pkt[1] != 0 && i < 2 { // marker only on the last packet
			t.Errorf("packet %d PT = %x, want 0", i, pkt[1]&0x7F)
		}
		i++
	})
	if seq != 3 {
		t.Errorf("seq = %d, want 3", seq)
	}
	if i != 3 {
		t.Errorf("packets = %d, want 3", i)
	}
}

func TestDigestAuthRoundTrip(t *testing.T) {
	a := NewAuth("user", "pass", "realm")
	challenge := a.Challenge()
	nonce := extractQuoted(challenge, "nonce")
	if nonce == "" {
		t.Fatal("no nonce in challenge")
	}
	uri := "rtsp://cam/doorcam"
	ha1 := md5hex("user:realm:pass")
	ha2 := md5hex("DESCRIBE:" + uri)
	resp := md5hex(ha1 + ":" + nonce + ":" + ha2) // RFC 2069 (no qop)
	header := `Digest username="user", realm="realm", nonce="` + nonce + `", uri="` + uri + `", response="` + resp + `"`
	if !a.Verify(header, "DESCRIBE") {
		t.Error("digest verify failed")
	}
	if a.Verify(header, "SETUP") {
		t.Error("digest verify must be method-sensitive")
	}
}

func extractQuoted(s, key string) string {
	i := strings.Index(s, key+"=\"")
	if i < 0 {
		return ""
	}
	rest := s[i+len(key)+2:]
	j := strings.IndexByte(rest, '"')
	return rest[:j]
}

// joinAnnexB joins NALs into one access unit with 4-byte start codes.
func joinAnnexB(nals ...[]byte) []byte {
	var out []byte
	sc := []byte{0, 0, 0, 1}
	for _, n := range nals {
		out = append(out, sc...)
		out = append(out, n...)
	}
	return out
}
