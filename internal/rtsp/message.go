package rtsp

import (
	"fmt"
	"strings"
)

// Message is a parsed RTSP request or response.
type Message struct {
	Method  string
	URL     string
	Proto   string // "RTSP/1.0"
	Code    int
	Status  string
	Headers map[string]string
	Body    []byte
}

// Header returns the header value (case-insensitive).
func (m *Message) Header(name string) string {
	if m.Headers == nil {
		return ""
	}
	return m.Headers[strings.ToLower(name)]
}

// SetHeader sets a header (name is stored lowercased).
func (m *Message) SetHeader(name, value string) {
	if m.Headers == nil {
		m.Headers = map[string]string{}
	}
	m.Headers[strings.ToLower(name)] = value
}

// ParseRequest reads one RTSP request from raw bytes.
func ParseRequest(data []byte) (*Message, error) {
	lines := strings.Split(string(data), "\r\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty message")
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed request line: %q", lines[0])
	}
	m := &Message{Method: parts[0], URL: parts[1], Proto: parts[2], Headers: map[string]string{}}
	bodyOffset := 0
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			bodyOffset = i + 1
			break
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			m.Headers[strings.ToLower(strings.TrimSpace(line[:idx]))] = strings.TrimSpace(line[idx+1:])
		}
	}
	// join remaining lines for body (handle CRLFs preserved by split)
	rest := strings.Join(lines[bodyOffset:], "\r\n")
	m.Body = []byte(rest)
	if cl := m.Header("Content-Length"); cl != "" {
		var n int
		fmt.Sscanf(cl, "%d", &n)
		if len(m.Body) > n {
			m.Body = m.Body[:n]
		}
	}
	return m, nil
}

// Marshal renders the message as bytes.
func (m *Message) Marshal(isResponse bool) []byte {
	var b strings.Builder
	m.Headers["content-length"] = fmt.Sprintf("%d", len(m.Body))
	if isResponse {
		fmt.Fprintf(&b, "%s %d %s\r\n", m.Proto, m.Code, m.Status)
	} else {
		fmt.Fprintf(&b, "%s %s %s\r\n", m.Method, m.URL, m.Proto)
	}
	for k, v := range m.Headers {
		// canonicalise common header names
		fmt.Fprintf(&b, "%s: %s\r\n", canonicalHeader(k), v)
	}
	b.WriteString("\r\n")
	b.Write(m.Body)
	return []byte(b.String())
}

func canonicalHeader(k string) string {
	switch k {
	case "cseq":
		return "CSeq"
	case "session":
		return "Session"
	case "content-length":
		return "Content-Length"
	case "content-type":
		return "Content-Type"
	case "content-base":
		return "Content-Base"
	case "www-authenticate":
		return "WWW-Authenticate"
	case "authorization":
		return "Authorization"
	case "transport":
		return "Transport"
	case "rtp-info":
		return "RTP-Info"
	case "public":
		return "Public"
	default:
		return strings.Title(k)
	}
}

// Response builds a basic response for a request.
func Response(req *Message, code int, status string) *Message {
	return &Message{
		Proto:   req.Proto,
		Code:    code,
		Status:  status,
		Headers: map[string]string{},
	}
}
