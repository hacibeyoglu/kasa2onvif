// Package onvif - service.go: the SOAP-over-HTTP device + media service.
//
// Responds to the operations exercised by UniFi Protect during discovery and
// adoption:
//   - GetSystemDateAndTime, GetCapabilities, GetServices, GetDeviceInformation
//   - GetProfiles, GetProfile, GetVideoSourceConfigurations,
//     GetVideoEncoderConfigurations, GetVideoSourceConfiguration,
//     GetVideoEncoderConfiguration, GetVideoEncoderConfigurationOptions
//   - GetStreamUri, GetSnapshotUri, GetNetworkInterfaces, GetScopes,
//     GetServiceCapabilities, SetSystemDateAndTime, SystemReboot
package onvif

import (
	"crypto/subtle"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// MediaInfo describes the single profile advertised to the client.
type MediaInfo struct {
	ProfileToken string
	ProfileName  string
	Width        int
	Height       int
	FPS          int
	Encoder      string // H264
	BitrateLimit int
	GOVLength    int
	RTSPURL      string // rtsp://host:port/path
	SnapshotURI  string
	AudioEncoder string // G711
	// HasAudio gates whether audio configuration elements appear in the
	// profile responses; UniFi Protect reads the profile to decide whether
	// to enable audio on the camera - a profile without audio config = a
	// mute camera in Protect.
	HasAudio bool
}

// audioConfigs returns the audio configuration fragments embedded in a
// media profile (G711 mu-law, 8kHz, mono - matches the Kasa stream).
func (m *MediaInfo) audioConfigs(indent string) string {
	if !m.HasAudio {
		return ""
	}
	return indent + `<trt:AudioSourceConfiguration token="ASC_000"><tt:Name>AudioSource_1</tt:Name><tt:SourceToken>AST_000</tt:SourceToken><tt:InputTokenActive>false</tt:InputTokenActive><tt:Channels>1</tt:Channels></trt:AudioSourceConfiguration>` +
		indent + `<trt:AudioEncoderConfiguration token="AEC_000"><tt:Name>Audio_1</tt:Name><tt:Encoding>G711</tt:Encoding><tt:Bitrate>64</tt:Bitrate><tt:SampleRate>8</tt:SampleRate><tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>0</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast><tt:SessionTimeout>PT10S</tt:SessionTimeout></trt:AudioEncoderConfiguration>`
}

// DeviceInfo describes the advertised device.
type DeviceInfo struct {
	Manufacturer string
	Model        string
	Firmware     string
	Serial       string
	Name         string
	HardwareID   string
	MAC          string
	IPAddress    string
}

// Service handles ONVIF SOAP requests on /onvif/device_service.
type Service struct {
	Info       *DeviceInfo
	Media      *MediaInfo
	Auth       *Auth
	TimeSource func() time.Time
	BootID     uint64
	Start      time.Time

	// advertise stores the runtime-computed address (host:port) used for
	// XAddrs when Info.IPAddress is empty; set from the request Host header.
	mu        sync.Mutex
	advertise string

	scopes []string
}

// advertAddr returns the http:// address advertised in XAddrs. Never empty:
// an empty host would make clients request paths like "/http://" (which
// answer 301 and break adoption).
func (s *Service) advertAddr() string {
	addr := s.Info.IPAddress
	if addr == "" {
		addr = s.advertise
	}
	if addr == "" {
		addr = "127.0.0.1:80"
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	return strings.TrimSuffix(addr, "/")
}

// SetAdvertise records the runtime host:port (called per-request when the
// Host header is known). Used when no static address is configured.
func (s *Service) SetAdvertise(hostPort string) {
	if hostPort == "" {
		return
	}
	// drop any path a client might send; keep host[:port]
	if i := strings.IndexByte(hostPort, '/'); i >= 0 {
		hostPort = hostPort[:i]
	}
	s.mu.Lock()
	s.advertise = hostPort
	s.mu.Unlock()
}

// NewService builds the ONVIF service.
func NewService(info *DeviceInfo, media *MediaInfo, auth *Auth) *Service {
	s := &Service{Info: info, Media: media, Auth: auth, TimeSource: time.Now, Start: time.Now()}
	// Strip scheme artifacts if a full URL was configured as the advert addr.
	addr := info.IPAddress
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimSuffix(addr, "/")
	info.IPAddress = addr
	s.scopes = []string{
		"onvif://www.onvif.org/Profile/Streaming",
		"onvif://www.onvif.org/Name/" + urlEscape(info.Name),
		"onvif://www.onvif.org/Hardware/" + urlEscape(info.HardwareID),
		"onvif://www.onvif.org/Model/" + urlEscape(info.Model),
		"onvif://www.onvif.org/MAC/" + strings.ReplaceAll(info.MAC, ":", ""),
		"onvif://www.onvif.org/Profile/S",
	}
	return s
}

// ServeHTTP implements the SOAP endpoint.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Never let a handler panic take down the connection abruptly (a panic
	// mid-response surfaces as ECONNRESET on the client).
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[onvif] panic recovered: %v\n%s", rec, debug.Stack())
			respondSOAPFault(w, "Receiver", "internal error")
		}
	}()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "ONVIF device service: POST only", http.StatusMethodNotAllowed)
		return
	}
	// Read the FULL body: a single Body.Read can truncate (the ws-secnonce
	// bytes may arrive in a later TCP segment), which breaks the digest.
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil || len(body) == 0 {
		w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
		w.WriteHeader(http.StatusOK) // SOAP faults ride on 200; 4xx can abort clients
		_, _ = w.Write([]byte(soapFault("Sender", "empty request")))
		return
	}
	action := extractAction(body)
	// Record the advertised address from the Host header (skipping the port
	// if it matches the listener default) so XAddrs are never empty.
	s.SetAdvertise(r.Host)
	// auth: allow the no-auth set (discovery-relevant queries); otherwise a
	// valid ws-username token OR HTTP Basic credentials are accepted (some
	// ONVIF clients use either).
	if !s.Auth.Verify(body) && !s.httpBasicOK(r) {
		log.Printf("[onvif] auth failed: action=%s user=%q (digest/basic mismatch or missing token)",
			action, s.Auth.recvUser(body))
		respondSOAPFault(w, "Sender", "Not authorized")
		return
	}
	fn, ok := handlers[strings.TrimSpace(action)]
	if !ok {
		// Unknown operations get an empty success envelope (not a 4xx/5xx):
		// several clients (incl. Protect's raw-socket path) abort adoption on
		// any HTTP error status.
		log.Printf("[onvif] stub: unhandled action %s -> empty response", action)
		_, _ = w.Write([]byte(envelope("")))
		return
	}
	log.Printf("[onvif] %s", action)
	out, err := fn(s, body)
	if err != nil {
		respondSOAPFault(w, "Receiver", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// httpBasicOK checks the HTTP Basic Authorization header against the ONVIF
// credentials.
func (s *Service) httpBasicOK(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(user), []byte(s.Auth.Username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(s.Auth.Password)) == 1
}

// extractAction finds the SOAP action from the body (wsa:Action or the
// operation element name).
func extractAction(body []byte) string {
	m := tagValue(body, "Action")
	if m != "" {
		if i := strings.LastIndexByte(m, '/'); i >= 0 {
			m = m[i+1:]
		}
		return m
	}
	// fallback: first operation element after <Body>. The wsse:Security
	// block (commonly placed inside Body) must be skipped, since it is not
	// the operation.
	s := string(body)
	for _, open := range []string{"<s:Body>", "<Body>", "<soap:Body>", "<env:Body>"} {
		i := strings.Index(s, open)
		if i < 0 {
			continue
		}
		rest := s[i+len(open):]
		for {
			idx := strings.IndexByte(rest, '<')
			if idx < 0 {
				break
			}
			rest = rest[idx+1:] // drop the '<'
			// is this the operation (a known ONVIF op) or a header block?
			nameMatch := regexp.MustCompile(`^(?:([A-Za-z0-9]+):)?([A-Za-z0-9]+)`).FindStringSubmatch(rest)
			if nameMatch == nil {
				rest = rest[strings.IndexByte(rest, '>')+1:]
				continue
			}
			local := nameMatch[2]
			if knownOps[local] {
				return local
			}
			// skip this element (advance past its closing tag)
			if strings.HasSuffix(rest[:len(nameMatch[0])+1], "/>") {
				rest = rest[len(nameMatch[0]):]
				continue
			}
			endTag := "</" + nameMatch[1] + ":" + local + ">"
			if nameMatch[1] == "" {
				endTag = "</" + local + ">"
			}
			if j := strings.Index(rest, endTag); j >= 0 {
				rest = rest[j+len(endTag):]
			} else {
				// self-closing or unknown: continue scanning after '<'
				rest = rest[len(nameMatch[0]):]
			}
		}
	}
	return ""
}

// knownOps is the set of ONVIF operation local-names this service handles,
// used by extractAction to skip Security/token blocks inside s:Body.
var knownOps = map[string]bool{
	"GetSystemDateAndTime": true, "SetSystemDateAndTime": true,
	"GetCapabilities": true, "GetServices": true, "GetServiceCapabilities": true,
	"GetDeviceInformation": true, "GetNetworkInterfaces": true,
	"GetScopes": true, "SetScopes": true,
	"GetProfiles": true, "GetProfile": true,
	"GetVideoSourceConfigurations": true, "GetVideoEncoderConfigurations": true,
	"GetVideoSourceConfiguration": true, "GetVideoEncoderConfiguration": true,
	"GetVideoEncoderConfigurationOptions": true,
	"GetStreamUri":                        true, "GetSnapshotUri": true, "SystemReboot": true,
	// adopted-sequence stubs (empty answers keep clients from aborting)
	"GetHostname": true, "SetHostname": true, "GetDNS": true, "SetDNS": true,
	"GetNTP": true, "SetNTP": true, "GetDynamicDNS": true, "SetDynamicDNS": true,
	"GetUsers":                     true,
	"GetVideoOutputConfigurations": true, "GetAudioSourceConfigurations": true,
	"GetAudioEncoderConfigurations": true, "GetAudioOutputs": true,
	"GetRelayOutputs": true, "GetDigitalInputs": true,
	"GetVideoSources": true, "GetVideoOutputs": true,
	"GetAudioOutputConfigurations": true, "GetAudioDecoderConfigurations": true,
	"GetGeoLocation": true, "SetGeoLocation": true,
	"GetStorageConfiguration": true, "GetStorageConfigurations": true,
	"GetDiscoveryMode": true, "SetDiscoveryMode": true,
	"StartSystemRestore": true,
}

// handlerFunc processes one ONVIF operation.
type handlerFunc func(s *Service, body []byte) (string, error)

var handlers = map[string]handlerFunc{
	"GetSystemDateAndTime":                (*Service).getSystemDateAndTime,
	"SetSystemDateAndTime":                (*Service).setSystemDateAndTime,
	"GetCapabilities":                     (*Service).getCapabilities,
	"GetServices":                         (*Service).getServices,
	"GetServiceCapabilities":              (*Service).getServiceCapabilities,
	"GetDeviceInformation":                (*Service).getDeviceInformation,
	"GetNetworkInterfaces":                (*Service).getNetworkInterfaces,
	"GetScopes":                           (*Service).getScopes,
	"SetScopes":                           (*Service).setScopes,
	"GetProfiles":                         (*Service).getProfiles,
	"GetProfile":                          (*Service).getProfile,
	"GetVideoSourceConfigurations":        (*Service).getVideoSourceConfigurations,
	"GetVideoEncoderConfigurations":       (*Service).getVideoEncoderConfigurations,
	"GetVideoSourceConfiguration":         (*Service).getVideoSourceConfiguration,
	"GetVideoEncoderConfiguration":        (*Service).getVideoEncoderConfiguration,
	"GetVideoEncoderConfigurationOptions": (*Service).getVideoEncoderConfigurationOptions,
	"GetStreamUri":                        (*Service).getStreamUri,
	"GetSnapshotUri":                      (*Service).getSnapshotUri,
	"SystemReboot":                        (*Service).systemReboot,
	// safe empty stubs for adoption-flow calls
	"GetHostname":                   (*Service).getHostname,
	"SetHostname":                   (*Service).emptyResponse,
	"GetDNS":                        (*Service).getDNS,
	"SetDNS":                        (*Service).emptyResponse,
	"GetNTP":                        (*Service).getNTP,
	"SetNTP":                        (*Service).emptyResponse,
	"GetDynamicDNS":                 (*Service).emptyResponse,
	"SetDynamicDNS":                 (*Service).emptyResponse,
	"GetUsers":                      (*Service).getUsers,
	"GetDiscoveryMode":              (*Service).getDiscoveryMode,
	"SetDiscoveryMode":              (*Service).emptyResponse,
	"GetGeoLocation":                (*Service).emptyResponse,
	"SetGeoLocation":                (*Service).emptyResponse,
	"GetVideoSources":               (*Service).getVideoSources,
	"GetVideoOutputs":               (*Service).emptyList,
	"GetAudioOutputs":               (*Service).emptyList,
	"GetAudioSourceConfigurations":  (*Service).getAudioSourceConfigurations,
	"GetAudioEncoderConfigurations": (*Service).getAudioEncoderConfigurations,
	"GetVideoOutputConfigurations":  (*Service).emptyList,
	"GetAudioOutputConfigurations":  (*Service).emptyList,
	"GetAudioDecoderConfigurations": (*Service).emptyList,
	"GetRelayOutputs":               (*Service).emptyResponse,
	"GetDigitalInputs":              (*Service).emptyResponse,
	"GetStorageConfigurations":      (*Service).emptyList}

// ---- envelope helpers ----

const soapNS = `xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:trt="http://www.onvif.org/ver10/media/wsdl"`

func envelope(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope ` + soapNS + `><s:Body>` + body + `</s:Body></s:Envelope>`
}

func respondSOAPFault(w http.ResponseWriter, code, reason string) {
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	_, _ = w.Write([]byte(soapFault(code, reason)))
}

// soapFault renders a SOAP 1.2 fault envelope (HTTP 200, per SOAP-over-HTTP
// binding - non-200 statuses make some clients fall back to raw sockets).
func soapFault(code, reason string) string {
	return envelope(`<s:Fault><s:Code><s:Value>soap:` + code + `</s:Value></s:Code><s:Reason><s:Text xml:lang="en">` + xmlEscape(reason) + `</s:Text></s:Reason></s:Fault>`)
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func urlEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "%20"), "/", "%2F")
}

// ---- handlers ----

func (s *Service) getSystemDateAndTime(_ []byte) (string, error) {
	now := s.TimeSource().UTC()
	out := fmt.Sprintf(`<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime>
<tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings>
<tt:TimeZone><tt:TZ>UTC</tt:TZ></tt:TimeZone>
<tt:UTCDateTime><tt:Time><tt:Hour>%d</tt:Hour><tt:Minute>%d</tt:Minute><tt:Second>%d</tt:Second></tt:Time>
<tt:Date><tt:Year>%d</tt:Year><tt:Month>%d</tt:Month><tt:Day>%d</tt:Day></tt:Date></tt:UTCDateTime>
</tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>`,
		now.Hour(), now.Minute(), now.Second(), now.Year(), int(now.Month()), now.Day())
	return envelope(out), nil
}

func (s *Service) setSystemDateAndTime([]byte) (string, error) {
	return envelope(""), nil
}

func (s *Service) getCapabilities([]byte) (string, error) {
	addr := s.advertAddr()
	out := `<tds:GetCapabilitiesResponse><tds:Capabilities>
<tt:Device><tt:XAddr>` + addr + `</tt:XAddr>
<tt:Network><tt:IPFilter>false</tt:IPFilter><tt:ZeroConfiguration>false</tt:ZeroConfiguration><tt:IPVersion6>false</tt:IPVersion6><tt:DynDNS>false</tt:DynDNS></tt:Network>
<tt:System><tt:DiscoveryResolve>true</tt:DiscoveryResolve><tt:DiscoveryByAddress>true</tt:DiscoveryByAddress><tt:Reboot>true</tt:Reboot><tt:SystemTime>NTP</tt:SystemTime></tt:System>
<tt:Security><tt:TLS1.1>false</tt:TLS1.1><tt:OnboardKeyGeneration>false</tt:OnboardKeyGeneration><tt:AccessPolicyConfig>false</tt:AccessPolicyConfig><tt:X.509Token>false</tt:X.509Token><tt:SAMLToken>false</tt:SAMLToken><tt:KerberosToken>false</tt:KerberosToken><tt:RelayToken>false</tt:RelayToken><tt:MD5Support>false</tt:MD5Support><tt:EAES128Support>false</tt:EAES128Support></tt:Security>
</tt:Device>
<tt:Media><tt:XAddr>` + addr + `</tt:XAddr><tt:StreamingCapabilities><tt:RTPMulticast>false</tt:RTPMulticast><tt:RTP_TCP>true</tt:RTP_TCP><tt:RTP_UDP>false</tt:RTP_UDP></tt:StreamingCapabilities></tt:Media>
</tds:Capabilities></tds:GetCapabilitiesResponse>`
	return envelope(out), nil
}

func (s *Service) getServices([]byte) (string, error) {
	addr := s.advertAddr()
	out := `<tds:GetServicesResponse>
<tds:Service><tt:Namespace>http://www.onvif.org/ver10/device/wsdl</tt:Namespace><tt:XAddr>` + addr + `</tt:XAddr><tt:Version><tt:Major>2</tt:Major><tt:Minor>0</tt:Minor></tt:Version></tds:Service>
<tds:Service><tt:Namespace>http://www.onvif.org/ver10/media/wsdl</tt:Namespace><tt:XAddr>` + addr + `</tt:XAddr><tt:Version><tt:Major>2</tt:Major><tt:Minor>0</tt:Minor></tt:Version></tds:Service>
</tds:GetServicesResponse>`
	return envelope(out), nil
}

func (s *Service) getServiceCapabilities([]byte) (string, error) {
	out := `<tds:GetServiceCapabilitiesResponse><tds:Capabilities><tt:DiscoveryByAddress>true</tt:DiscoveryByAddress>`
	return envelope(out + `</tds:Capabilities></tds:GetServiceCapabilitiesResponse>`), nil
}

func (s *Service) getDeviceInformation([]byte) (string, error) {
	out := fmt.Sprintf(`<tds:GetDeviceInformationResponse>
<tds:Manufacturer>%s</tds:Manufacturer><tds:Model>%s</tds:Model><tds:FirmwareVersion>%s</tds:FirmwareVersion><tds:SerialNumber>%s</tds:SerialNumber><tds:HardwareId>%s</tds:HardwareId>
</tds:GetDeviceInformationResponse>`,
		xmlEscape(s.Info.Manufacturer), xmlEscape(s.Info.Model), xmlEscape(s.Info.Firmware), xmlEscape(s.Info.Serial), xmlEscape(s.Info.HardwareID))
	return envelope(out), nil
}

func (s *Service) getNetworkInterfaces([]byte) (string, error) {
	mac := s.Info.MAC
	if mac == "" {
		mac = "00:00:00:00:00:01" // placeholder keeps the schema valid
	}
	out := `<tds:GetNetworkInterfacesResponse>
<tds:NetworkInterfaces token="eth0">
<tt:Enabled>true</tt:Enabled>
<tt:Info><tt:Name>eth0</tt:Name><tt:HwAddress>` + mac + `</tt:HwAddress><tt:MTU>1500</tt:MTU></tt:Info>
</tds:NetworkInterfaces>
</tds:GetNetworkInterfacesResponse>`
	return envelope(out), nil
}

func (s *Service) getScopes([]byte) (string, error) {
	var b strings.Builder
	for _, sc := range s.scopes {
		b.WriteString(`<tt:Scopes><tt:ScopeDef>Fixed</tt:ScopeDef><tt:ScopeItem>`)
		b.WriteString(sc)
		b.WriteString(`</tt:ScopeItem></tt:Scopes>`)
	}
	return envelope(`<tds:GetScopesResponse>` + b.String() + `</tds:GetScopesResponse>`), nil
}

func (s *Service) setScopes([]byte) (string, error) {
	return envelope(""), nil
}

func (s *Service) getProfiles([]byte) (string, error) {
	m := s.Media
	out := fmt.Sprintf(`<trt:GetProfilesResponse><trt:Profiles token="%s" fixed="true">
<tt:Name>%s</tt:Name>
<trt:VideoSourceConfiguration token="VSP_000"><tt:Name>VideoSource_1</tt:Name><tt:SourceToken>VST_000</tt:SourceToken><tt:Bounds x="0" y="0" width="%d" height="%d"/></trt:VideoSourceConfiguration>
<trt:VideoEncoderConfiguration token="VEC_000"><tt:Name>H264</tt:Name><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height></tt:Resolution><tt:RateControl><tt:FrameRateLimit>%d</tt:FrameRateLimit><tt:BitrateLimit>%d</tt:BitrateLimit></tt:RateControl><tt:H264><tt:GovLength>%d</tt:GovLength><tt:Profiles>Main</tt:Profiles></tt:H264><tt:SessionTimeout>PT10S</tt:SessionTimeout></trt:VideoEncoderConfiguration>
%s</trt:Profiles></trt:GetProfilesResponse>`,
		m.ProfileToken, xmlEscape(m.ProfileName), m.Width, m.Height, m.Width, m.Height, m.FPS, m.BitrateLimit, m.GOVLength, m.audioConfigs(""))
	return envelope(out), nil
}

func (s *Service) getProfile(_ []byte) (string, error) {
	return s.getProfiles(nil)
}

func (s *Service) getVideoSourceConfigurations([]byte) (string, error) {
	m := s.Media
	out := fmt.Sprintf(`<trt:GetVideoSourceConfigurationsResponse><trt:Configurations token="VSP_000"><tt:Name>VideoSource_1</tt:Name><tt:SourceToken>VST_000</tt:SourceToken><tt:Bounds x="0" y="0" width="%d" height="%d"/></trt:Configurations></trt:GetVideoSourceConfigurationsResponse>`, m.Width, m.Height)
	return envelope(out), nil
}

func (s *Service) getVideoEncoderConfigurations([]byte) (string, error) {
	m := s.Media
	out := fmt.Sprintf(`<trt:GetVideoEncoderConfigurationsResponse><trt:Configurations token="VEC_000"><tt:Name>H264</tt:Name><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height></tt:Resolution><tt:RateControl><tt:FrameRateLimit>%d</tt:FrameRateLimit><tt:BitrateLimit>%d</tt:BitrateLimit></tt:RateControl><tt:H264><tt:GovLength>%d</tt:GovLength><tt:Profiles>Main</tt:Profiles></tt:H264><tt:SessionTimeout>PT10S</tt:SessionTimeout></trt:Configurations></trt:GetVideoEncoderConfigurationsResponse>`,
		m.Width, m.Height, m.FPS, m.BitrateLimit, m.GOVLength)
	return envelope(out), nil
}

func (s *Service) getVideoSourceConfiguration([]byte) (string, error) {
	m := s.Media
	out := fmt.Sprintf(`<trt:GetVideoSourceConfigurationResponse><trt:Configuration token="VSP_000"><tt:Name>VideoSource_1</tt:Name><tt:SourceToken>VST_000</tt:SourceToken><tt:Bounds x="0" y="0" width="%d" height="%d"/></trt:Configuration></trt:GetVideoSourceConfigurationResponse>`, m.Width, m.Height)
	return envelope(out), nil
}

func (s *Service) getVideoEncoderConfiguration([]byte) (string, error) {
	m := s.Media
	out := fmt.Sprintf(`<trt:GetVideoEncoderConfigurationResponse><trt:Configuration token="VEC_000"><tt:Name>H264</tt:Name><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height></tt:Resolution><tt:RateControl><tt:FrameRateLimit>%d</tt:FrameRateLimit><tt:BitrateLimit>%d</tt:BitrateLimit></tt:RateControl><tt:H264><tt:GovLength>%d</tt:GovLength><tt:Profiles>Main</tt:Profiles></tt:H264><tt:SessionTimeout>PT10S</tt:SessionTimeout></trt:Configuration></trt:GetVideoEncoderConfigurationResponse>`,
		m.Width, m.Height, m.FPS, m.BitrateLimit, m.GOVLength)
	return envelope(out), nil
}

func (s *Service) getAudioSourceConfigurations([]byte) (string, error) {
	if !s.Media.HasAudio {
		return envelope(""), nil
	}
	return envelope(`<trt:GetAudioSourceConfigurationsResponse><trt:Configurations token="ASC_000"><tt:Name>AudioSource_1</tt:Name><tt:SourceToken>AST_000</tt:SourceToken><tt:Channels>1</tt:Channels></trt:Configurations></trt:GetAudioSourceConfigurationsResponse>`), nil
}

func (s *Service) getAudioEncoderConfigurations([]byte) (string, error) {
	if !s.Media.HasAudio {
		return envelope(""), nil
	}
	return envelope(`<trt:GetAudioEncoderConfigurationsResponse><trt:Configurations token="AEC_000"><tt:Name>Audio_1</tt:Name><tt:Encoding>G711</tt:Encoding><tt:Bitrate>64</tt:Bitrate><tt:SampleRate>8</tt:SampleRate><tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>0</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast><tt:SessionTimeout>PT10S</tt:SessionTimeout></trt:Configurations></trt:GetAudioEncoderConfigurationsResponse>`), nil
}

func (s *Service) getVideoEncoderConfigurationOptions([]byte) (string, error) {
	m := s.Media
	out := fmt.Sprintf(`<trt:GetVideoEncoderConfigurationOptionsResponse><trt:Options><tt:QualityRange><tt:Min>1</tt:Min><tt:Max>10</tt:Max></tt:QualityRange><tt:H264><tt:ResolutionsAvailable><tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height></tt:Resolution></tt:ResolutionsAvailable><tt:GovLengthRange><tt:Min>1</tt:Min><tt:Max>64</tt:Max></tt:GovLengthRange><tt:FrameRateRange><tt:Min>1</tt:Min><tt:Max>%d</tt:Max></tt:FrameRateRange><tt:EncodingIntervalRange><tt:Min>1</tt:Min><tt:Max>1</tt:Max></tt:EncodingIntervalRange><tt:H264ProfilesSupported>Main</tt:H264ProfilesSupported></tt:H264></trt:Options></trt:GetVideoEncoderConfigurationOptionsResponse>`,
		m.Width, m.Height, m.FPS)
	return envelope(out), nil
}

func (s *Service) getStreamUri([]byte) (string, error) {
	out := `<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>` + xmlEscape(s.Media.RTSPURL) + `</tt:Uri>
<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect><tt:InvalidAfterReboot>false</tt:InvalidAfterReboot><tt:Timeout>PT10S</tt:Timeout></trt:MediaUri></trt:GetStreamUriResponse>`
	return envelope(out), nil
}

func (s *Service) getSnapshotUri([]byte) (string, error) {
	out := `<trt:GetSnapshotUriResponse><trt:MediaUri><tt:Uri>` + xmlEscape(s.Media.SnapshotURI) + `</tt:Uri>
<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect><tt:InvalidAfterReboot>false</tt:InvalidAfterReboot><tt:Timeout>PT10S</tt:Timeout></trt:MediaUri></trt:GetSnapshotUriResponse>`
	return envelope(out), nil
}

func (s *Service) systemReboot([]byte) (string, error) {
	return envelope(`<tds:SystemRebootResponse><tds:Message>Rebooting</tds:Message></tds:SystemRebootResponse>`), nil
}

// ---- adoption-flow stubs (schema-shaped, minimally populated) ----

func (s *Service) emptyResponse([]byte) (string, error) { return envelope(""), nil }

func (s *Service) emptyList([]byte) (string, error) { return envelope(""), nil }

func (s *Service) getHostname([]byte) (string, error) {
	name := "camproxy"
	return envelope(`<tds:GetHostnameResponse><tds:HostnameInformation><tt:Name>` + name + `</tt:Name><tt:FromDHCP>false</tt:FromDHCP></tds:HostnameInformation></tds:GetHostnameResponse>`), nil
}

func (s *Service) getDNS([]byte) (string, error) {
	ip := s.Info.IPAddress
	if ip == "" || ip == "http://" {
		ip = "0.0.0.0"
	}
	out := `<tds:GetDNSResponse><tds:DNSInformation><tt:FromDHCP>false</tt:FromDHCP><tt:DNSManual><tt:Type>IPv4</tt:Type><tt:IPv4Address>` + ip + `</tt:IPv4Address></tt:DNSManual></tds:DNSInformation></tds:GetDNSResponse>`
	return envelope(out), nil
}

func (s *Service) getNTP([]byte) (string, error) {
	return envelope(`<tds:GetNTPResponse><tds:NTPInformation><tt:FromDHCP>false</tt:FromDHCP></tds:NTPInformation></tds:GetNTPResponse>`), nil
}

func (s *Service) getUsers([]byte) (string, error) {
	// Report the ONVIF account itself (Protect may compare or just read).
	u := xmlEscape(s.Auth.Username)
	return envelope(`<tds:GetUsersResponse><tds:User><tt:Username>` + u + `</tt:Username><tt:UserLevel>Admin</tt:UserLevel></tds:User></tds:GetUsersResponse>`), nil
}

func (s *Service) getDiscoveryMode([]byte) (string, error) {
	return envelope(`<tds:GetDiscoveryModeResponse><tds:DiscoveryMode>Discoverable</tds:DiscoveryMode></tds:GetDiscoveryModeResponse>`), nil
}

func (s *Service) getVideoSources([]byte) (string, error) {
	m := s.Media
	out := fmt.Sprintf(`<tds:GetVideoSourcesResponse><tds:VideoSources token="VST_000"><tt:ProfileToken>%s</tt:ProfileToken>`+
		`<tt:VideoSourceConfiguration><tt:Name>VideoSource_1</tt:Name><tt:SourceToken>VST_000</tt:SourceToken><tt:Bounds x="0" y="0" width="%d" height="%d"/></tt:VideoSourceConfiguration></tds:VideoSources></tds:GetVideoSourcesResponse>`,
		m.ProfileToken, m.Width, m.Height)
	return envelope(out), nil
}

// JustifyIP returns the IPv4 address of the given interface (falling back to
// any non-loopback IPv4, then loopback).
func JustifyIP(iface string) string {
	if iface != "" {
		if ifc, err := net.InterfaceByName(iface); err == nil {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					return ipn.IP.String()
				}
			}
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "127.0.0.1"
}
