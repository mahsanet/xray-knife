package xray

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/GFW-knocker/Xray-core/proxy/masque"
	"github.com/fatih/color"
)

// Defaults MahsaNG fills in for parameters a masque:// link leaves out
// (MasqueFmt.parse and AppConfig), so a link behaves the same in both.
const (
	masqueDefaultTransport = "h2"
	masqueDefaultAddress   = "172.16.0.2/32"
	masqueDefaultMTU       = 1280
	masqueDefaultDNS       = "1.1.1.1"
	masqueDefaultKeepAlive = 5
	masqueDefaultPort      = "443"

	// Built-in noise ahead of the QUIC handshake (HTTP/3 only), as in
	// MahsaNG's WireGuard defaults.
	masqueDefaultWnoise       = "quic"
	masqueDefaultWnoisecount  = "15"
	masqueDefaultWnoisedelay  = "1-2"
	masqueDefaultWpayloadsize = "5-10"
)

var masquePinPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func NewMasque(link string) Protocol {
	return &Masque{OrigLink: link}
}

func (m *Masque) Name() string {
	return protocol.MasqueIdentifier
}

// Parse reads the link MahsaNG writes (MasqueFmt):
//
//	masque://<PEM body of the private key>@<host>:<port>?transport=h2&address=...&sni=...#remark
//
// MahsaNG encodes the query and remark with Java's URLEncoder, so "+" is a
// space there; the key is standard base64, where a raw "+" stays a "+".
func (m *Masque) Parse() error {
	prefix := protocol.MasqueIdentifier + "://"
	if !strings.HasPrefix(m.OrigLink, prefix) {
		return fmt.Errorf("masque unreconized: %s", m.OrigLink)
	}

	// Split by hand rather than with url.Parse: an unencoded "/" in the
	// base64 key would end the URL authority early.
	base, rawRemark, _ := strings.Cut(m.OrigLink, "#")
	m.Remark = formUnescape(rawRemark)
	body := strings.TrimPrefix(base, prefix)
	body, rawQuery, _ := strings.Cut(body, "?")
	at := strings.LastIndex(body, "@")
	if at <= 0 {
		return errors.New("masque link has no private key")
	}
	key, err := masquePrivateKey(lenientUnescape(body[:at]))
	if err != nil {
		return err
	}
	m.PrivateKey = key

	host, port, err := masqueHostPort(strings.TrimSuffix(body[at+1:], "/"))
	if err != nil {
		return err
	}
	m.Endpoint = net.JoinHostPort(host, port)

	q := url.Values{}
	for pair := range strings.SplitSeq(rawQuery, "&") {
		k, v, _ := strings.Cut(pair, "=")
		if k = formUnescape(k); k != "" {
			q.Add(k, formUnescape(v))
		}
	}
	get := func(def string, names ...string) string {
		for _, name := range names {
			if vs, ok := q[name]; ok && len(vs) > 0 {
				return strings.TrimSpace(vs[0])
			}
		}
		return def
	}
	atoi := func(name, s string) (int32, error) {
		n, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid masque %s %q", name, s)
		}
		return int32(n), nil
	}

	switch t := strings.ToLower(get("", "transport")); t {
	case "h2", "h3":
		m.Transport = t
	default:
		m.Transport = masqueDefaultTransport
	}
	m.Address = get(masqueDefaultAddress, "address")
	if len(splitList(m.Address)) == 0 {
		m.Address = masqueDefaultAddress
	}
	if m.MTU, err = atoi("mtu", get(strconv.Itoa(masqueDefaultMTU), "mtu")); err != nil {
		return err
	}
	m.RemoteDNS = get(masqueDefaultDNS, "remoteDNS", "dns")
	m.DomainStrategy = get("", "domainStrategy")
	if m.KeepAlive, err = atoi("keepalive", get(strconv.Itoa(masqueDefaultKeepAlive), "keepalive", "keepAlivePeriod")); err != nil {
		return err
	}
	m.Pins = get("", "pinnedPeerPublicKeySha256", "pin")
	for _, pin := range splitList(m.Pins) {
		if !masquePinPattern.MatchString(pin) {
			return fmt.Errorf("invalid masque pin %q: want 64 hex digits (SHA-256 of the public key)", pin)
		}
	}
	m.Wnoise = get(masqueDefaultWnoise, "wnoise")
	m.Wnoisecount = get(masqueDefaultWnoisecount, "wnoisecount")
	m.Wnoisedelay = get(masqueDefaultWnoisedelay, "wnoisedelay")
	m.Wpayloadsize = get(masqueDefaultWpayloadsize, "wpayloadsize")

	// Fragment uses the same keys as MahsaNG's vless links; it splits TCP,
	// so only the HTTP/2 carrier uses it.
	m.FragmentPackets = get("", "packets")
	m.FragmentLength = get("", "length")
	m.FragmentInterval = get("", "interval")

	// "sni=" present but empty is a deliberate request for no SNI.
	m.SNI = get(masque.DefaultSNI, "sni")
	if m.SNI != "" && !validSNI(m.SNI) {
		return fmt.Errorf("invalid masque sni %q", m.SNI)
	}
	// Insecure unless the link says otherwise, as in MahsaNG.
	m.Insecure = get("", "insecure") != "0" && get("", "allowInsecure") != "0"
	// Base64 has no spaces: a raw "+" decoded as one is put back.
	m.ECHConfigList = strings.ReplaceAll(get("", "echConfigList", "ech"), " ", "+")
	m.FinalMask = get("", "fm")
	return nil
}

// masqueHostPort splits the endpoint; the port defaults to 443 as in MahsaNG.
func masqueHostPort(hostport string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(hostport)
	if err != nil {
		host, port = unbracket(hostport), masqueDefaultPort
	}
	if host == "" || strings.ContainsAny(host, "/?#@ ") {
		return "", "", fmt.Errorf("invalid masque endpoint %q", hostport)
	}
	if _, err := parsePort(port); err != nil {
		return "", "", fmt.Errorf("invalid masque endpoint %q: %w", hostport, err)
	}
	return host, port, nil
}

// masquePrivateKey turns the key a link carries (a PEM, or just its base64
// body) into the PEM the core wants: "PRIVATE KEY" (PKCS#8) or "EC PRIVATE
// KEY" (SEC1), checked with the core's own parser.
func masquePrivateKey(text string) (string, error) {
	// Also accept a key pasted straight out of a JSON string.
	text = strings.TrimSpace(strings.ReplaceAll(text, `\n`, "\n"))
	if text == "" {
		return "", errors.New("masque link has no private key")
	}
	if strings.EqualFold(text, "auto") {
		return "", errors.New(`masque key "auto" stands for the key stored inside MahsaNG, which only the app has; export the link with its real key`)
	}
	der, err := decodeBase64Loose(pemBody(text))
	if err != nil {
		return "", fmt.Errorf("masque private key is not base64: %w", err)
	}
	pemType := "PRIVATE KEY"
	if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
		if _, err := x509.ParseECPrivateKey(der); err != nil {
			return "", errors.New("masque private key is neither PKCS#8 nor SEC1 EC")
		}
		pemType = "EC PRIVATE KEY"
	}
	key := string(pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}))
	if _, err := masque.ParsePrivateKey(key); err != nil {
		return "", fmt.Errorf("invalid masque private key: %w", err)
	}
	return key, nil
}

// pemBody returns a PEM's base64 body, armour and whitespace removed; any
// other text comes back with only its whitespace removed.
func pemBody(text string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-----") {
			continue
		}
		b.WriteString(line)
	}
	return strings.Join(strings.Fields(b.String()), "")
}

func decodeBase64Loose(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("illegal base64 data")
}

// formUnescape decodes like Java's URLDecoder ("+" is a space), keeping
// malformed escapes literally.
func formUnescape(s string) string {
	if v, err := url.QueryUnescape(s); err == nil {
		return v
	}
	return lenientUnescape(strings.ReplaceAll(s, "+", " "))
}

func (m *Masque) host() (host, port string) {
	host, port, _ = net.SplitHostPort(m.Endpoint)
	return host, port
}

func (m *Masque) DetailsStr() string {
	sni := m.SNI
	if sni == "" {
		sni = "(none)"
	}
	key := pemBody(m.PrivateKey)
	if len(key) > 16 {
		key = key[:16] + "..."
	}
	return fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %d\n%s: %v\n%s: %s\n",
		color.RedString("Protocol"), m.Name(),
		color.RedString("Remark"), m.Remark,
		color.RedString("Endpoint"), m.Endpoint,
		color.RedString("Transport"), m.Transport,
		color.RedString("SNI"), sni,
		color.RedString("Local Addresses"), m.Address,
		color.RedString("MTU"), m.MTU,
		color.RedString("Insecure"), m.Insecure,
		color.RedString("Private Key"), key,
	)
}

// GetLink returns the original link, or rebuilds one the way MahsaNG
// writes it (MasqueFmt.toUri).
func (m *Masque) GetLink() string {
	if m.OrigLink != "" {
		return m.OrigLink
	}
	var q []string
	add := func(k, v string) {
		if v != "" {
			q = append(q, k+"="+url.QueryEscape(v))
		}
	}
	add("transport", m.Transport)
	add("address", m.Address)
	if m.MTU != 0 {
		add("mtu", strconv.Itoa(int(m.MTU)))
	}
	add("remoteDNS", m.RemoteDNS)
	add("domainStrategy", m.DomainStrategy)
	q = append(q, "sni="+url.QueryEscape(m.SNI))
	if m.Insecure {
		q = append(q, "insecure=1")
	} else {
		q = append(q, "insecure=0")
	}
	add("pinnedPeerPublicKeySha256", m.Pins)
	add("echConfigList", m.ECHConfigList)
	add("keepalive", strconv.Itoa(int(m.KeepAlive)))
	add("wnoise", m.Wnoise)
	add("wnoisecount", m.Wnoisecount)
	add("wnoisedelay", m.Wnoisedelay)
	add("wpayloadsize", m.Wpayloadsize)
	add("packets", m.FragmentPackets)
	add("length", m.FragmentLength)
	add("interval", m.FragmentInterval)
	add("fm", m.FinalMask)
	return fmt.Sprintf("masque://%s@%s?%s#%s",
		url.QueryEscape(pemBody(m.PrivateKey)), m.Endpoint, strings.Join(q, "&"), url.QueryEscape(m.Remark))
}

func (m *Masque) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = m.Name()
	g.Address, g.Port = m.host()
	g.Remark = m.Remark
	g.Network = "tcp"
	if m.Transport == "h3" {
		g.Network = "udp"
	}
	g.Type = m.Transport
	g.TLS = "tls"
	g.SNI = m.SNI
	g.ALPN = m.Transport
	g.OrigLink = m.GetLink()
	return g
}

// masqueSettings is the core's "masque" outbound settings (conf.MasqueConfig).
type masqueSettings struct {
	Endpoint                  string   `json:"endpoint"`
	Address                   []string `json:"address"`
	PrivateKey                string   `json:"privateKey"`
	Transport                 string   `json:"transport"`
	MTU                       int32    `json:"mtu,omitempty"`
	RemoteDNS                 []string `json:"remoteDNS,omitempty"`
	DomainStrategy            string   `json:"domainStrategy,omitempty"`
	KeepAlivePeriod           int32    `json:"keepAlivePeriod,omitempty"`
	PinnedPeerPublicKeySha256 []string `json:"pinnedPeerPublicKeySha256,omitempty"`
	Wnoise                    string   `json:"wnoise,omitempty"`
	Wnoisecount               string   `json:"wnoisecount,omitempty"`
	Wnoisedelay               string   `json:"wnoisedelay,omitempty"`
	Wpayloadsize              string   `json:"wpayloadsize,omitempty"`
}

// BuildOutboundDetourConfig builds the core's native "masque" outbound,
// as MahsaNG's MasqueFmt.toXrayOutbound does. TLS (server name, ECH,
// allowInsecure) comes from streamSettings like any other outbound. No
// fingerprint is set: a uTLS ClientHello carries no client certificate,
// and MASQUE is mutual TLS.
func (m *Masque) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	h3 := m.Transport == "h3"
	settings := masqueSettings{
		Endpoint:                  m.Endpoint,
		Address:                   splitList(m.Address),
		PrivateKey:                m.PrivateKey,
		Transport:                 m.Transport,
		MTU:                       m.MTU,
		RemoteDNS:                 splitList(m.RemoteDNS),
		DomainStrategy:            m.DomainStrategy,
		KeepAlivePeriod:           m.KeepAlive,
		PinnedPeerPublicKeySha256: splitList(m.Pins),
	}
	// The core's built-in noise is HTTP/3 only; "none" turns it off.
	if h3 && m.Wnoise != "" && !strings.EqualFold(m.Wnoise, "none") {
		settings.Wnoise = m.Wnoise
		settings.Wnoisecount = m.Wnoisecount
		settings.Wnoisedelay = m.Wnoisedelay
		settings.Wpayloadsize = m.Wpayloadsize
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("marshal masque settings: %w", err)
	}
	rawMsg := json.RawMessage(raw)

	alpn := conf.StringList{m.Transport}
	stream := &conf.StreamConfig{
		Security: "tls",
		TLSSettings: &conf.TLSConfig{
			AllowInsecure: allowInsecure || m.Insecure,
			// Empty is passed on: the core then sends no SNI.
			ServerName:    m.SNI,
			ALPN:          &alpn,
			ECHConfigList: m.ECHConfigList,
		},
	}
	if m.FinalMask != "" {
		stream.FinalMask = &conf.FinalMask{}
		if err := json.Unmarshal([]byte(m.FinalMask), stream.FinalMask); err != nil {
			return nil, fmt.Errorf("invalid masque fm (finalmask JSON): %w", err)
		}
	}
	if !h3 && m.FragmentPackets != "" {
		frag := map[string]string{"packets": m.FragmentPackets}
		if m.FragmentLength != "" {
			frag["length"] = m.FragmentLength
		}
		// The finalmask key is "delay"; an unknown key is silently ignored.
		if m.FragmentInterval != "" {
			frag["delay"] = m.FragmentInterval
		}
		fragRaw, err := json.Marshal(frag)
		if err != nil {
			return nil, err
		}
		fragMsg := json.RawMessage(fragRaw)
		if stream.FinalMask == nil {
			stream.FinalMask = &conf.FinalMask{}
		}
		stream.FinalMask.Tcp = append(stream.FinalMask.Tcp, conf.Mask{Type: "fragment", Settings: &fragMsg})
	}

	return &conf.OutboundDetourConfig{
		Tag:           "proxy",
		Protocol:      m.Name(),
		Settings:      &rawMsg,
		StreamSetting: stream,
	}, nil
}

func (m *Masque) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, fmt.Errorf("creating a MASQUE inbound from a client link is not supported")
}

// masqueTransport reads the carrier from a built masque outbound.
func masqueTransport(ob *conf.OutboundDetourConfig) string {
	if ob.Settings == nil {
		return ""
	}
	var s struct {
		Transport string `json:"transport"`
	}
	_ = json.Unmarshal(*ob.Settings, &s)
	return strings.ToLower(s.Transport)
}
