package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v10/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v10/utils"

	"github.com/fatih/color"
	"github.com/GFW-knocker/Xray-core/infra/conf"
)

func NewHysteria2(link string) Protocol {
	return &Hysteria2{OrigLink: link}
}

func (h *Hysteria2) Name() string {
	return protocol.Hysteria2Identifier
}

func (h *Hysteria2) Parse() error {
	uri, err := url.Parse(h.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse Hysteria2 link: %w", err)
	}

	// Accept both "hysteria2://" and the common "hy2://" alias.
	if uri.Scheme != protocol.Hysteria2Identifier && uri.Scheme != "hy2" {
		return fmt.Errorf("hysteria2/hy2 unrecognized scheme: %s", uri.Scheme)
	}

	h.Password = uri.User.String() // Hysteria2 auth string (password)

	h.Address, h.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for Hysteria2 link: %w", err)
	}

	if utils.IsIPv6(h.Address) {
		h.Address = "[" + h.Address + "]"
	}

	query := uri.Query()
	h.SNI = strings.TrimSpace(query.Get("sni"))
	h.ObfusType = query.Get("obfs")
	h.ObfusPassword = query.Get("obfs-password")
	h.Insecure = query.Get("insecure") // "0", "1", "false", "true"

	if h.SNI != "" && !utils.IsValidHostOrSNI(h.SNI) {
		return fmt.Errorf("invalid characters in 'sni' parameter: %s", h.SNI)
	}

	unescapedRemark, err := url.PathUnescape(uri.Fragment)
	if err != nil {
		h.Remark = uri.Fragment
	} else {
		h.Remark = unescapedRemark
	}

	// Hysteria2 mandates TLS, which needs a server name. Fall back to the
	// address when SNI is omitted.
	if h.SNI == "" {
		h.SNI = h.Address
	}

	return nil
}

func (h *Hysteria2) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), h.Name(),
		color.RedString("Remark"), h.Remark,
		color.RedString("Network"), "quic",
		color.RedString("Address"), h.Address,
		color.RedString("Port"), h.Port,
		color.RedString("SNI"), h.SNI)

	if h.Insecure != nil && h.Insecure != "" {
		info += fmt.Sprintf("%s: %v\n", color.RedString("Insecure"), h.Insecure)
	}
	if h.ObfusType != "" {
		// xray-core's hysteria transport has no obfs support (salamander);
		// surface it so the user knows it won't be applied on this core.
		info += fmt.Sprintf("%s: %s (unsupported on xray core)\n%s: %s\n",
			color.RedString("Obfs"), h.ObfusType,
			color.RedString("Obfs-Password"), h.ObfusPassword)
	}
	return info
}

func (h *Hysteria2) GetLink() string {
	if h.OrigLink != "" {
		return h.OrigLink
	}
	baseURL := url.URL{
		Scheme: protocol.Hysteria2Identifier,
		User:   url.User(h.Password),
		Host:   net.JoinHostPort(h.Address, h.Port),
	}
	params := url.Values{}
	addQueryParam := func(key, value string) {
		if value != "" {
			params.Add(key, value)
		}
	}
	addQueryParam("sni", h.SNI)
	addQueryParam("obfs", h.ObfusType)
	addQueryParam("obfs-password", h.ObfusPassword)
	if s, ok := h.Insecure.(string); ok {
		addQueryParam("insecure", s)
	}
	baseURL.RawQuery = params.Encode()
	if h.Remark != "" {
		baseURL.Fragment = h.Remark
	}
	return baseURL.String()
}

func (h *Hysteria2) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = h.Name()
	g.Address = h.Address
	g.Port = h.Port
	g.Remark = h.Remark
	g.SNI = h.SNI
	g.TLS = "tls"
	g.OrigLink = h.GetLink()
	return g
}

func (h *Hysteria2) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	portNum, err := strconv.ParseUint(h.Port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", h.Port, err)
	}

	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	// xray-core registers this proxy under the name "hysteria" (Hysteria2).
	out.Protocol = "hysteria"

	// Outbound settings only carry version + endpoint (HysteriaClientConfig).
	settingsBytes, err := json.Marshal(map[string]interface{}{
		"version": 2,
		"address": h.Address,
		"port":    portNum,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal hysteria2 settings: %w", err)
	}
	oset := json.RawMessage(settingsBytes)
	out.Settings = &oset

	// The auth string lives in the transport's hysteriaSettings; TLS/SNI is
	// read from the stream security settings (tls.ConfigFromStreamSettings).
	network := conf.TransportProtocol("hysteria")
	s := &conf.StreamConfig{
		Network:  &network,
		Security: "tls",
		HysteriaSettings: &conf.HysteriaConfig{
			Version: 2,
			Auth:    h.Password,
		},
	}

	insecure := allowInsecure
	if str, ok := h.Insecure.(string); ok && (str == "1" || str == "true") {
		insecure = true
	}
	if b, ok := h.Insecure.(bool); ok && b {
		insecure = true
	}

	s.TLSSettings = &conf.TLSConfig{
		ServerName: h.SNI,
	}
	s.TLSSettings.AllowInsecure = insecure // see vless.go

	out.StreamSetting = s
	return out, nil
}

func (h *Hysteria2) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, fmt.Errorf("creating a Hysteria2 inbound from a client link is not supported")
}
