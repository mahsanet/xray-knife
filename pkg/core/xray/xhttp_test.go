package xray

import (
	"net/url"
	"testing"

	"github.com/GFW-knocker/Xray-core/transport/internet/splithttp"
)

// xhttp extra must reach the core as is, including the new sessionID* keys.
func TestXHTTPExtraReachesCore(t *testing.T) {
	extra := url.QueryEscape(`{"sessionIDPlacement":"cookie","sessionIDKey":"sid","sessionIDLength":"16-32","xPaddingBytes":"100-1000"}`)
	q := "?security=tls&sni=a.com&type=xhttp&mode=packet-up&path=%2Fx&extra=" + extra
	for _, link := range []string{
		"vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443" + q + "&encryption=none",
		"mvless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443" + q + "&encryption=none",
		"trojan://pw@1.2.3.4:443" + q,
	} {
		p, err := (&Core{}).CreateProtocol(link)
		if err != nil {
			t.Fatal(err)
		}
		xp := p.(Protocol)
		if err := xp.Parse(); err != nil {
			t.Fatal(err)
		}
		ob, err := xp.BuildOutboundDetourConfig(false)
		if err != nil {
			t.Fatal(err)
		}
		ss, err := ob.StreamSetting.Build()
		if err != nil {
			t.Fatalf("%s: %v", link[:6], err)
		}
		var cfg *splithttp.Config
		for _, ts := range ss.TransportSettings {
			if m, err := ts.GetTypedSettings(); err == nil {
				if c, ok := m.(*splithttp.Config); ok {
					cfg = c
				}
			}
		}
		if cfg == nil {
			t.Fatalf("%s: no xhttp config", link[:6])
		}
		if cfg.SessionIDPlacement != "cookie" || cfg.SessionIDKey != "sid" || cfg.SessionIDLength.GetFrom() != 16 {
			t.Fatalf("%s: session = %q %q %v", link[:6], cfg.SessionIDPlacement, cfg.SessionIDKey, cfg.SessionIDLength)
		}
		if _, err := ob.Build(); err != nil {
			t.Fatalf("%s: Build: %v", link[:6], err)
		}
	}
}
