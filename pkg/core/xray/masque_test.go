package xray

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/GFW-knocker/Xray-core/infra/conf"
)

// masqueKeyBody returns the base64 body of a fresh P-256 key, PKCS#8 or
// SEC1, as a masque:// link carries it.
func masqueKeyBody(t *testing.T, sec1 bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var der []byte
	if sec1 {
		der, err = x509.MarshalECPrivateKey(key)
	} else {
		der, err = x509.MarshalPKCS8PrivateKey(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func parseMasque(t *testing.T, link string) *Masque {
	t.Helper()
	return parseLink(t, link).(*Masque)
}

func masqueStream(t *testing.T, m *Masque) *conf.StreamConfig {
	t.Helper()
	ob, err := m.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatalf("BuildOutboundDetourConfig: %v", err)
	}
	return ob.StreamSetting
}

// TestMasqueParsesMahsaNGLink: a link as MahsaNG's MasqueFmt.toUri writes
// it (URLEncoder: key and values percent-encoded, "+" for a space).
func TestMasqueParsesMahsaNGLink(t *testing.T) {
	body := masqueKeyBody(t, false)
	link := "masque://" + url.QueryEscape(body) + "@162.159.198.1:443?transport=h3&address=172.16.0.2%2F32" +
		"&mtu=1280&remoteDNS=1.1.1.1&sni=&insecure=0&keepalive=5&wnoise=quicinit&wnoisecount=1" +
		"&wnoisedelay=1-2&wpayloadsize=5-10&domainStrategy=ForceIPv4#My+Masque+%F0%9F%9A%80"
	m := parseMasque(t, link)

	if m.Remark != "My Masque 🚀" || m.Endpoint != "162.159.198.1:443" || m.Transport != "h3" ||
		m.SNI != "" || m.Insecure || m.Wnoise != "quicinit" || m.DomainStrategy != "ForceIPv4" {
		t.Fatalf("parsed = %+v", m)
	}
	if pemBody(m.PrivateKey) != body || !strings.HasPrefix(m.PrivateKey, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("key = %q", m.PrivateKey)
	}

	settings := buildOK(t, m)
	want := map[string]interface{}{
		"endpoint": "162.159.198.1:443", "transport": "h3", "mtu": 1280.0, "keepAlivePeriod": 5.0,
		"wnoise": "quicinit", "wnoisecount": "1", "domainStrategy": "ForceIPv4",
	}
	for k, v := range want {
		if settings[k] != v {
			t.Errorf("settings[%s] = %v, want %v", k, settings[k], v)
		}
	}
	if addr, _ := settings["address"].([]interface{}); len(addr) != 1 || addr[0] != "172.16.0.2/32" {
		t.Errorf("address = %v", settings["address"])
	}

	s := masqueStream(t, m)
	tls := s.TLSSettings
	if s.Security != "tls" || tls.ServerName != "" || tls.AllowInsecure || tls.Fingerprint != "" ||
		tls.ALPN == nil || len(*tls.ALPN) != 1 || (*tls.ALPN)[0] != "h3" {
		t.Errorf("stream = %+v, tls = %+v", s, tls)
	}

	ob, _ := m.BuildOutboundDetourConfig(false)
	if !usesUDP(ob) {
		t.Error("h3 masque should count as UDP")
	}
	if g := m.ConvertToGeneralConfig(); g.Protocol != "masque" || g.Address != "162.159.198.1" || g.Port != "443" || g.Network != "udp" {
		t.Errorf("general = %+v", g)
	}
}

// TestMasqueDefaults: what MahsaNG fills in for a bare link.
func TestMasqueDefaults(t *testing.T) {
	m := parseMasque(t, "masque://"+url.QueryEscape(masqueKeyBody(t, false))+"@[2606:4700:103::1]")
	if m.Endpoint != "[2606:4700:103::1]:443" || m.Transport != "h2" || m.Address != "172.16.0.2/32" ||
		m.MTU != 1280 || m.RemoteDNS != "1.1.1.1" || m.KeepAlive != 5 || !m.Insecure ||
		m.SNI != "consumer-masque.cloudflareclient.com" {
		t.Fatalf("defaults = %+v", m)
	}
	settings := buildOK(t, m)
	if _, ok := settings["wnoise"]; ok {
		t.Errorf("noise is HTTP/3 only, got it on h2: %v", settings)
	}
	ob, _ := m.BuildOutboundDetourConfig(false)
	if usesUDP(ob) {
		t.Error("h2 masque should count as TCP")
	}
	if tls := ob.StreamSetting.TLSSettings; tls.ServerName != "consumer-masque.cloudflareclient.com" || !tls.AllowInsecure {
		t.Errorf("tls = %+v", tls)
	}
}

// TestMasqueKeyForms: a raw key ("/", "+" unescaped), a percent-encoded
// one, a full PEM and a SEC1 key all parse to the same kind of PEM.
func TestMasqueKeyForms(t *testing.T) {
	var body string
	for range 200 {
		if body = masqueKeyBody(t, false); strings.ContainsAny(body, "/") && strings.Contains(body, "+") {
			break
		}
	}
	raw := parseMasque(t, "masque://"+body+"@1.2.3.4:443?transport=h2")
	enc := parseMasque(t, "masque://"+url.QueryEscape(body)+"@1.2.3.4:443?transport=h2")
	if raw.PrivateKey != enc.PrivateKey || pemBody(raw.PrivateKey) != body {
		t.Fatalf("raw and encoded keys differ:\n%s\n%s", raw.PrivateKey, enc.PrivateKey)
	}

	pemKey := "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n"
	if p := parseMasque(t, "masque://"+url.QueryEscape(pemKey)+"@1.2.3.4:443"); p.PrivateKey != raw.PrivateKey {
		t.Errorf("PEM key = %q", p.PrivateKey)
	}

	sec1 := parseMasque(t, "masque://"+url.QueryEscape(masqueKeyBody(t, true))+"@1.2.3.4:443")
	if !strings.HasPrefix(sec1.PrivateKey, "-----BEGIN EC PRIVATE KEY-----") {
		t.Errorf("SEC1 key = %q", sec1.PrivateKey)
	}
	buildOK(t, sec1)
}

func TestMasqueRejects(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	key := url.QueryEscape(masqueKeyBody(t, false))

	for name, link := range map[string]string{
		"auto key":     "masque://auto@1.2.3.4:443",
		"no key":       "masque://@1.2.3.4:443",
		"not base64":   "masque://not*a*key@1.2.3.4:443",
		"not a key":    "masque://" + base64.StdEncoding.EncodeToString([]byte("hello world, not DER")) + "@1.2.3.4:443",
		"rsa key":      "masque://" + url.QueryEscape(base64.StdEncoding.EncodeToString(rsaDER)) + "@1.2.3.4:443",
		"bad pin":      "masque://" + key + "@1.2.3.4:443?pin=abcd",
		"bad port":     "masque://" + key + "@1.2.3.4:99999",
		"no host":      "masque://" + key + "@:443",
		"bad mtu":      "masque://" + key + "@1.2.3.4:443?mtu=big",
		"bad sni":      "masque://" + key + "@1.2.3.4:443?sni=a%20b",
		"wrong scheme": "wireguard://" + key + "@1.2.3.4:443",
	} {
		m := &Masque{OrigLink: link}
		if err := m.Parse(); err == nil {
			t.Errorf("%s: parsed %q", name, link)
		}
	}

	// Parsed fine, but the core rejects it when building.
	m := parseMasque(t, "masque://"+key+"@1.2.3.4:443?fm=%7Bnot+json")
	if _, err := m.BuildOutboundDetourConfig(false); err == nil {
		t.Error("invalid fm JSON built")
	}
}

// TestMasqueFragmentAndFinalMask: link fragment keys become a TCP
// "fragment" mask (with "delay", the key the core reads) on h2 only, after
// the masks from "fm".
func TestMasqueFragmentAndFinalMask(t *testing.T) {
	key := url.QueryEscape(masqueKeyBody(t, false))
	fm := url.QueryEscape(`{"tcp":[{"type":"header-custom","settings":{"clients":[]}}]}`)
	m := parseMasque(t, "masque://"+key+"@1.2.3.4:443?transport=h2&packets=1-1&length=10-20&interval=1-2&fm="+fm)
	s := masqueStream(t, m)
	if s.FinalMask == nil || len(s.FinalMask.Tcp) != 2 || s.FinalMask.Tcp[0].Type != "header-custom" || s.FinalMask.Tcp[1].Type != "fragment" {
		t.Fatalf("finalmask = %+v", s.FinalMask)
	}
	var frag map[string]string
	if err := json.Unmarshal(*s.FinalMask.Tcp[1].Settings, &frag); err != nil {
		t.Fatal(err)
	}
	if frag["packets"] != "1-1" || frag["length"] != "10-20" || frag["delay"] != "1-2" {
		t.Errorf("fragment = %v", frag)
	}
	buildOK(t, m) // the core accepts both masks

	h3 := parseMasque(t, "masque://"+key+"@1.2.3.4:443?transport=h3&packets=1-1&length=10-20&interval=1-2")
	if s := masqueStream(t, h3); s.FinalMask != nil {
		t.Errorf("h3 got a TCP fragment: %+v", s.FinalMask)
	}
}

// TestMasqueECHKeepsPlus: a raw "+" in a base64 ECH config is not a space.
func TestMasqueECHKeepsPlus(t *testing.T) {
	m := parseMasque(t, "masque://"+url.QueryEscape(masqueKeyBody(t, false))+"@1.2.3.4:443?ech=AEX+xyz/A=")
	if m.ECHConfigList != "AEX+xyz/A=" {
		t.Errorf("ech = %q", m.ECHConfigList)
	}
}

// TestMasqueLinkRoundTrip: a rebuilt link parses back to the same config.
func TestMasqueLinkRoundTrip(t *testing.T) {
	key := url.QueryEscape(masqueKeyBody(t, false))
	m := parseMasque(t, "masque://"+key+"@162.159.198.1:2053?transport=h3&sni=&insecure=0&pin="+
		strings.Repeat("ab", 32)+"&wnoise=none&packets=1-1#Edge+1")
	m.OrigLink = ""
	link := m.GetLink()
	if !strings.HasPrefix(link, "masque://") {
		t.Fatalf("link = %q", link)
	}
	back := parseMasque(t, link)
	back.OrigLink = ""
	if *back != *m {
		t.Errorf("round trip changed the config:\n got %+v\nwant %+v\nlink %s", back, m, link)
	}
}
