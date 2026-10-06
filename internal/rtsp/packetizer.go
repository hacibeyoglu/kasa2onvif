// Package rtsp implements the proxy RTSP server: it serves the hub stream to
// clients (UniFi Protect) as interleaved RTP-over-TCP with RFC 6184 H.264
// packetization and G.711 audio, with Digest-or-Basic authentication.
package rtsp

import (
	"encoding/binary"
)

// SampleEntry describes a single NAL unit to packetize.
type SampleEntry struct {
	Payload   []byte // STAP-A assembled or FU-A payload
	Marker    bool
	Timestamp uint32 // RTP timestamp (90kHz video / 8kHz audio)
	PT        uint8  // payload type
	SSRC      uint32
	Seq       uint16
	Channel   byte // interleaved channel (even = rtp)
}

// Packet builds a full RTP packet with the given header fields and payload.
func Packet(pt uint8, ssrc uint32, seq uint16, ts uint32, marker bool, payload []byte) []byte {
	pkt := make([]byte, 12+len(payload))
	pkt[0] = 0x80 // V=2, P=0, X=0, CC=0
	pkt[1] = pt   // M=0 initially
	if marker {
		pkt[1] |= 0x80
	}
	binary.BigEndian.PutUint16(pkt[2:], seq)
	binary.BigEndian.PutUint32(pkt[4:], ts)
	binary.BigEndian.PutUint32(pkt[8:], ssrc)
	copy(pkt[12:], payload)
	return pkt
}

// H264Packetizer fragments an Annex-B access unit into RTP packets per
// RFC 6184: SPS/PPS are carried in STAP-A, big NALs use FU-A with the config
// max packet size.
type H264Packetizer struct {
	MaxPayload int // default 1400
}

func NewH264Packetizer() *H264Packetizer {
	return &H264Packetizer{MaxPayload: 1400}
}

// NALHeaderType returns the NAL type of the payload's first NAL.
func nalType(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0] & 0x1F
}

// Packetize converts an Annex-B access unit into RTP packets. It emits:
//   - one STAP-A containing all small controlling NALs (SPS/PPS/AUD/SEI)
//   - for each slice NAL (type 1 or 5): a single packet (if it fits) or FU-A
//     fragments.
//
// The caller supplies the initial sequence number; the returned value is the
// next sequence number to use.
func (p *H264Packetizer) Packetize(au []byte, ssrc uint32, seq uint16, ts uint32, emit func([]byte, bool)) uint16 {
	type nalu struct {
		hdr byte
		b   []byte
	}
	var nalus []nalu
	i := 0
	for i < len(au) {
		n := startCode(au[i:])
		if n == 0 {
			i++
			continue
		}
		start := i + n
		j := start
		for j < len(au) {
			if k := startCode(au[j:]); k > 0 {
				break
			}
			j++
		}
		end := j
		for end > start && au[end-1] == 0 {
			end--
		}
		if end > start {
			nalus = append(nalus, nalu{hdr: au[start], b: au[start+1 : end]})
		}
		i = j
	}
	if len(nalus) == 0 {
		return seq
	}

	// STAP-A: aggregate all the small non-slice NALs (SPS=7, PPS=8, SEI=6,
	// AUD=9, filler=12) into one packet so decoders get parameters first.
	var stap []byte
	nri := byte(0)
	for _, n := range nalus {
		t := n.hdr & 0x1F
		if t == 1 || t == 5 {
			continue // slices are packetized separately below
		}
		if n.hdr&0x60 > nri {
			nri = n.hdr & 0x60
		}
		var sz [2]byte
		binary.BigEndian.PutUint16(sz[:], uint16(len(n.b)+1))
		stap = append(stap, sz[:]...)
		stap = append(stap, n.hdr)
		stap = append(stap, n.b...)
	}
	if len(stap) > 0 {
		stapHdr := 24 | nri // STAP-A with the highest aggregated NRI
		emit(Packet(96, ssrc, seq, ts, false, append([]byte{stapHdr}, stap...)), false)
		seq++
	}

	for _, n := range nalus {
		t := n.hdr & 0x1F
		if t != 1 && t != 5 {
			continue
		}
		full := len(n.b) + 1
		if full <= p.MaxPayload {
			// fits in a single NAL unit packet (marker = end of AU)
			emit(Packet(96, ssrc, seq, ts, true, append([]byte{n.hdr}, n.b...)), true)
			seq++
			continue
		}
		// FU-A: 1 byte FU indicator + 1 byte FU header + payload chunks
		rest := n.b
		first := true
		for len(rest) > 0 {
			c := p.MaxPayload - 2
			if len(rest) < c {
				c = len(rest)
			}
			chunk := rest[:c]
			rest = rest[c:]
			last := len(rest) == 0
			ind := (n.hdr & 0x60) | 28 // preserve NRI, FU-A type
			fh := n.hdr & 0x1F
			if first {
				fh |= 0x80 // S bit
			}
			if last {
				fh |= 0x40 // E bit
			}
			emit(Packet(96, ssrc, seq, ts, last, append([]byte{ind, fh}, chunk...)), last)
			seq++
			first = false
		}
	}
	return seq
}

func txt(t byte) bool { return t == 6 || t == 7 || t == 8 || t == 9 }

func startCode(b []byte) int {
	if len(b) >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 1 {
		return 4
	}
	if len(b) >= 3 && b[0] == 0 && b[1] == 0 && b[2] == 1 {
		return 3
	}
	return 0
}

// G711Packetizer chunks an audio payload into RTP packets of the given size
// (20ms at 8kHz = 160 bytes), incrementing both seq and timestamp.
func G711Packetize(payload []byte, ssrc uint32, seq uint16, ts uint32, chunk int, emit func([]byte, bool)) uint16 {
	if chunk <= 0 {
		chunk = 160
	}
	for len(payload) > 0 {
		c := chunk
		if len(payload) < c {
			c = len(payload)
		}
		last := c == len(payload)
		emit(Packet(0, ssrc, seq, ts, last, payload[:c]), last)
		seq++
		ts += uint32(c)
		payload = payload[c:]
	}
	return seq
}
