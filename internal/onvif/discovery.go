// Package onvif - discovery.go: WS-Discovery responder. Listens on UDP
// 239.255.255.250:3702 and answers Probe requests (from UniFi Protect and
// other ONVIF clients) announcing this proxy as a NetworkVideoTransmitter.
package onvif

import (
	"net"
	"strings"
	"sync"
	"time"
)

// Discovery answers WS-Discovery probes.
type Discovery struct {
	Iface  string // empty = all interfaces
	XAddr  string // e.g. 192.168.1.50:8080 (service address)
	Scopes string // space-separated scope list

	conn *net.UDPConn
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewDiscovery creates the responder.
func NewDiscovery(iface, xaddr, scopes string) *Discovery {
	return &Discovery{Iface: iface, XAddr: xaddr, Scopes: scopes, seen: map[string]time.Time{}}
}

// Run listens until stop is closed.
func (d *Discovery) Run(stop <-chan struct{}) error {
	addr := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 3702}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	d.conn = conn
	defer conn.Close()

	// Also bind the unicast socket so directed probes (unicast To) work.
	// Multicast group membership covers the common case.

	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return err
			}
		}
		select {
		case <-stop:
			return nil
		default:
		}
		msg := buf[:n]
		if !strings.Contains(string(msg), "Probe") {
			continue
		}
		msgID := extractProbeMessageID(msg)
		if d.dedup(msgID) {
			continue
		}
		reply := d.probeMatches(msgID, from)
		_, _ = conn.WriteToUDP([]byte(reply), from)
	}
}

// dedup remembers probe message IDs for 3s to avoid answering repeats.
func (d *Discovery) dedup(id string) bool {
	if id == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for k, t := range d.seen {
		if now.Sub(t) > 3*time.Second {
			delete(d.seen, k)
		}
	}
	if _, ok := d.seen[id]; ok {
		return true
	}
	d.seen[id] = now
	return false
}

// probeMatches builds the ProbeMatches response XML.
func (d *Discovery) probeMatches(msgID string, from *net.UDPAddr) string {
	if msgID == "" {
		msgID = "urn:uuid:unknown"
	}
	relates := msgID
	msgIDOut := "urn:uuid:" + randomHex(8) + "-" + randomHex(4) + "-" + randomHex(4) + "-" + randomHex(4) + "-" + randomHex(12)
	addr := d.XAddr
	scopes := d.Scopes
	return `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
<s:Header>
<a:MessageID>` + msgIDOut + `</a:MessageID>
<a:RelatesTo>` + relates + `</a:RelatesTo>
<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>
<d:AppSequence InstanceId="1" MessageNumber="1"/>
</s:Header>
<s:Body>
<d:ProbeMatches>
<d:ProbeMatch>
<a:EndpointReference><a:Address>urn:uuid:` + deviceUUID(addr) + `</a:Address></a:EndpointReference>
<d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
<d:Scopes>` + scopes + `</d:Scopes>
<d:XAddrs>http://` + addr + `/onvif/device_service</d:XAddrs>
<d:MetadataVersion>1</d:MetadataVersion>
</d:ProbeMatch>
</d:ProbeMatches>
</s:Body>
</s:Envelope>`
}

// deviceUUID derives a stable UUID from the address.
func deviceUUID(addr string) string {
	// Simple deterministic UUID from the address (UUIDv5-like but local)
	const hexdigits = "0123456789abcdef"
	h := uint32(2166136261)
	for i := 0; i < len(addr); i++ {
		h ^= uint32(addr[i])
		h *= 16777619
	}
	u := ""
	for i := 0; i < 32; i++ {
		// deterministic pseudo-random digits
		h = h*1664525 + 1013904223
		u += string(hexdigits[(h>>16)&0xF])
	}
	return u[:8] + "-" + u[8:12] + "-" + u[12:16] + "-" + u[16:20] + "-" + u[20:32]
}

// extractProbeMessageID extracts the wsa:MessageID of a probe.
func extractProbeMessageID(msg []byte) string {
	s := string(msg)
	start := strings.Index(s, "MessageID")
	if start < 0 {
		return ""
	}
	gt := strings.IndexByte(s[start:], '>')
	lt := strings.IndexByte(s[start:], '<')
	if gt < 0 || lt < 0 || lt < gt {
		return ""
	}
	return s[start+gt+1 : start+lt]
}
