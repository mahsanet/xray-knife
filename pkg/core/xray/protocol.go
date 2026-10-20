package xray

import (
	"errors"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// NormalizeLink trims a share link and lower-cases its scheme, so
// "VLESS://..." parses like "vless://...". Links without "://" are
// returned trimmed.
func NormalizeLink(link string) string {
	link = strings.TrimSpace(link)
	scheme, rest, found := strings.Cut(link, "://")
	if !found {
		return link
	}
	return strings.ToLower(scheme) + "://" + rest
}

func (c *Core) CreateProtocol(configLink string) (protocol.Protocol, error) {
	configLink = NormalizeLink(configLink)

	if mtproto.IsProxyLink(configLink) {
		return nil, mtproto.ErrNotProxyable
	}

	// Read the scheme without url.Parse: a remark such as "#100%" is not
	// a valid URL fragment, but the link is otherwise fine.
	scheme, _, found := strings.Cut(configLink, "://")
	if !found {
		return nil, errors.New("invalid xray protocol")
	}

	switch scheme {
	case protocol.VmessIdentifier:
		return NewVmess(configLink), nil
	case protocol.VlessIdentifier:
		return NewVless(configLink), nil
	case protocol.ShadowsocksIdentifier:
		return NewShadowsocks(configLink), nil
	case protocol.TrojanIdentifier:
		return NewTrojan(configLink), nil
	case protocol.SocksIdentifier, "socks5", "socks5h":
		return NewSocks(configLink), nil
	case protocol.WireguardIdentifier:
		return NewWireguard(configLink), nil
	case protocol.Hysteria2Identifier, "hy2":
		return NewHysteria2(configLink), nil
	default:
		return nil, errors.New("invalid xray protocol")
	}
}

// SingboxReason reports why a parsed link should run on sing-box rather
// than xray-core, or "" when xray can carry it. insecure is the caller's
// global --insecure setting. Reasons:
//   - a transport xray-core removed (h2/http),
//   - a Shadowsocks plugin or legacy stream cipher.
//
// The Mahsa core still honours allowInsecure, VLESS and Trojan without TLS
// and quic, so those links stay on xray.
func SingboxReason(p Protocol, insecure bool) string {
	switch v := p.(type) {
	case *Shadowsocks:
		if v.Plugin != "" {
			// Only move plugins sing-box implements; others fail on both
			// cores, and xray reports that clearly at build time.
			name, _, _ := strings.Cut(v.Plugin, ";")
			switch strings.TrimSpace(name) {
			case "obfs-local", "simple-obfs", "v2ray-plugin":
				return "shadowsocks plugin " + name
			}
			return ""
		}
		return v.xrayUnsupported()
	case *Vless:
		ts := v.transport()
		return removedTransport(&ts)
	case *Trojan:
		ts := v.transport()
		return removedTransport(&ts)
	case *Vmess:
		ts := v.transport()
		return removedTransport(&ts)
	}
	return ""
}

// removedTransport reports a transport only sing-box still implements.
func removedTransport(t *transportSpec) string {
	switch n := t.network(); n {
	case "h2", "http", "h3":
		return "transport " + n + " (removed from xray-core)"
	}
	return ""
}
