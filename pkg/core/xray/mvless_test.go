package xray

import (
	"strings"
	"testing"
)

const mvlessID = "a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5"

// TestMVlessBuildsAsMVless: an mvless link parses with the VLESS parser and
// builds through the shared stream builder, but runs as "mvless", which the
// GFW-knocker core must accept.
func TestMVlessBuildsAsMVless(t *testing.T) {
	for _, link := range []string{
		"mvless://" + mvlessID + "@1.2.3.4:443?security=tls&type=ws&sni=a.com&path=%2Fws#Speed 100%",
		"MVLESS://" + mvlessID + "@1.2.3.4:443?security=tls&type=tcp&sni=a.com",
		"mvless://" + mvlessID + "@1.2.3.4:443?security=reality&type=tcp&sni=a.com&pbk=1w_Ype94utCGbZoJnk3xAmpP4NCY3SnufFs9qNiSot0&sid=ab&fp=chrome",
		"mvless://" + mvlessID + "@1.2.3.4:443?security=tls&type=quic&sni=a.com&quicSecurity=aes-128-gcm&key=k",
		"mvless://" + mvlessID + "@1.2.3.4:443?security=tls&type=xhttp&sni=a.com&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D",
		"mvless://" + mvlessID + "@1.2.3.4:80?security=none&type=grpc&serviceName=svc",
	} {
		p := parseLink(t, link)
		if name := p.(*Vless).Name(); name != "mvless" {
			t.Errorf("%s: Name() = %q", link, name)
		}
		ob, err := p.BuildOutboundDetourConfig(false)
		if err != nil {
			t.Fatalf("%s: BuildOutboundDetourConfig: %v", link, err)
		}
		if ob.Protocol != "mvless" {
			t.Errorf("%s: outbound protocol = %q", link, ob.Protocol)
		}
		if _, err := ob.Build(); err != nil {
			t.Errorf("%s: ob.Build(): %v", link, err)
		}
	}
}

// TestMVlessSharesVlessFeatures: options the shared builder handles reach
// mvless too, and gRPC defaults to gun mode like VLESS.
func TestMVlessSharesVlessFeatures(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	p := parseLink(t, "mvless://"+mvlessID+"@1.2.3.4:443?security=tls&type=grpc&serviceName=svc&sni=a.com&pcs="+pin+"&ech=AEX%2Bxyz")
	ob, err := p.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	tls := ob.StreamSetting.TLSSettings
	if tls == nil || tls.PinnedPeerCertSha256 != pin || tls.ECHConfigList != "AEX+xyz" {
		t.Errorf("TLS settings not passed through: %+v", tls)
	}
	if g := ob.StreamSetting.GRPCSettings; g == nil || g.MultiMode {
		t.Errorf("gRPC settings = %+v, want gun mode", g)
	}
}

// TestMVlessLinkRoundTrip: a rebuilt link keeps the mvless scheme and
// parses back as mvless.
func TestMVlessLinkRoundTrip(t *testing.T) {
	p := parseLink(t, "mvless://"+mvlessID+"@1.2.3.4:443?security=tls&type=ws&sni=a.com#m")
	v := p.(*Vless)
	v.OrigLink = "" // force GetLink to rebuild the link
	link := v.GetLink()
	if !strings.HasPrefix(link, "mvless://") {
		t.Fatalf("GetLink() = %q", link)
	}
	if name := parseLink(t, link).(*Vless).Name(); name != "mvless" {
		t.Errorf("round trip parsed as %q", name)
	}
	if g := p.ConvertToGeneralConfig(); g.Protocol != "mvless" {
		t.Errorf("GeneralConfig protocol = %q", g.Protocol)
	}
}

// TestMVlessStaysOnXray: sing-box has no mvless, so the automatic core must
// never move an mvless link there, even for a transport it would move for
// VLESS.
func TestMVlessStaysOnXray(t *testing.T) {
	for _, q := range []string{"security=tls&type=ws&sni=a.com", "security=tls&type=h2&sni=a.com"} {
		if r := SingboxReason(parseLink(t, "mvless://"+mvlessID+"@1.2.3.4:443?"+q)); r != "" {
			t.Errorf("mvless %s moves to sing-box: %s", q, r)
		}
	}
}

// TestMVlessInbound: the inbound is an mvless inbound, which the core accepts.
func TestMVlessInbound(t *testing.T) {
	p := parseLink(t, "mvless://"+mvlessID+"@127.0.0.1:10443?security=none&type=ws&path=%2Fws")
	in, err := p.BuildInboundDetourConfig()
	if err != nil {
		t.Fatal(err)
	}
	if in.Protocol != "mvless" {
		t.Errorf("inbound protocol = %q", in.Protocol)
	}
	if _, err := in.Build(); err != nil {
		t.Errorf("in.Build(): %v", err)
	}
}
