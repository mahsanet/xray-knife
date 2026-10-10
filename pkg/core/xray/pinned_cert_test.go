package xray

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A 32-byte SHA-256 in hex, the form xray-core's pinnedPeerCertSha256 accepts.
const testPinnedSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func b64VmessPinned(pcs string) string {
	payload := map[string]any{
		"v": "2", "ps": "pinned", "add": "1.2.3.4", "port": "443",
		"id": "a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5", "aid": "0", "scy": "auto",
		"net": "ws", "type": "none", "host": "example.com", "path": "/",
		"tls": "tls", "sni": "example.com", "fp": "chrome", "pcs": pcs,
	}
	b, _ := json.Marshal(payload)
	return base64.StdEncoding.EncodeToString(b)
}

// The `pcs` query parameter (xray share-link spec) must survive Parse → GetLink.
func TestPinnedPeerCertSha256_LinkRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		link string
	}{
		{"vless", "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?encryption=none&security=tls&type=tcp&sni=example.com&pcs=" + testPinnedSha256},
		{"trojan", "trojan://password@1.2.3.4:443?security=tls&type=tcp&sni=example.com&pcs=" + testPinnedSha256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := (&Core{}).CreateProtocol(tc.link)
			if err != nil {
				t.Fatalf("CreateProtocol: %v", err)
			}
			xp := p.(Protocol)
			if err := xp.Parse(); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			u, err := url.Parse(xp.GetLink())
			if err != nil {
				t.Fatalf("parse generated link: %v", err)
			}
			if got := u.Query().Get("pcs"); got != testPinnedSha256 {
				t.Errorf("GetLink pcs = %q, want %q", got, testPinnedSha256)
			}
			if !strings.Contains(xp.DetailsStr(), testPinnedSha256) {
				t.Errorf("DetailsStr does not mention the pinned cert hash")
			}
		})
	}
}

// pcs must reach xray-core's TLS settings and pass its Build() validation,
// for every TLS-capable xray protocol. Two comma-separated pins in OpenSSL
// colon form prove the value is handed over verbatim (xray splits/normalizes).
func TestPinnedPeerCertSha256_BuildsTLSSettings(t *testing.T) {
	colon := strings.ToUpper(testPinnedSha256)
	var parts []string
	for i := 0; i < len(colon); i += 2 {
		parts = append(parts, colon[i:i+2])
	}
	twoPins := testPinnedSha256 + "," + strings.Join(parts, ":")

	cases := []struct {
		name string
		link string
		want string
	}{
		{"vless", "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?encryption=none&security=tls&type=tcp&sni=example.com&pcs=" + url.QueryEscape(twoPins), twoPins},
		{"trojan", "trojan://password@1.2.3.4:443?security=tls&type=tcp&sni=example.com&pcs=" + url.QueryEscape(testPinnedSha256), testPinnedSha256},
		{"vmess", "vmess://" + b64VmessPinned(testPinnedSha256), testPinnedSha256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := (&Core{}).CreateProtocol(tc.link)
			if err != nil {
				t.Fatalf("CreateProtocol: %v", err)
			}
			xp := p.(Protocol)
			if err := xp.Parse(); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			ob, err := xp.BuildOutboundDetourConfig(false)
			if err != nil {
				t.Fatalf("BuildOutboundDetourConfig: %v", err)
			}
			tls := ob.StreamSetting.TLSSettings
			if tls == nil {
				t.Fatalf("expected TLSSettings")
			}
			if tls.PinnedPeerCertSha256 != tc.want {
				t.Errorf("PinnedPeerCertSha256 = %q, want %q", tls.PinnedPeerCertSha256, tc.want)
			}
			if _, err := ob.Build(); err != nil {
				t.Fatalf("ob.Build() rejected the pinned cert config: %v", err)
			}
		})
	}
}

// Without pcs nothing changes: the field stays empty and Build() still works.
func TestPinnedPeerCertSha256_AbsentLeavesTLSUntouched(t *testing.T) {
	v := &Vless{OrigLink: "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?encryption=none&security=tls&type=tcp&sni=example.com"}
	if err := v.Parse(); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ob, err := v.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatalf("BuildOutboundDetourConfig: %v", err)
	}
	if ob.StreamSetting.TLSSettings.PinnedPeerCertSha256 != "" {
		t.Errorf("PinnedPeerCertSha256 = %q, want empty", ob.StreamSetting.TLSSettings.PinnedPeerCertSha256)
	}
	if strings.Contains(v.GetLink(), "pcs=") {
		t.Errorf("GetLink emitted an empty pcs param: %s", v.GetLink())
	}
}

// End to end through xray-core: the pin must actually gate the TLS handshake.
// A local TLS server with a self-signed cert stands in for the proxy. With the
// right pin xray completes TLS and the (non-trojan) server answers the trojan
// preamble with an HTTP 400; with a wrong pin xray refuses the handshake and
// the request fails. Without pinning a self-signed cert would fail CA checks,
// so a 400 on the right pin proves pcs is what made the connection succeed.
func TestPinnedPeerCertSha256_EnforcedByXrayCore(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	rightPin := hex.EncodeToString(sum[:])
	wrongPin := strings.Repeat("00", 32)
	addr := strings.TrimPrefix(srv.URL, "https://")

	get := func(t *testing.T, pin string) (int, error) {
		t.Helper()
		link := fmt.Sprintf("trojan://password@%s?security=tls&type=tcp&sni=example.com&fp=chrome&pcs=%s", addr, pin)
		x := NewXrayService(false, false)
		p, err := x.CreateProtocol(link)
		if err != nil {
			t.Fatalf("CreateProtocol: %v", err)
		}
		if err := p.Parse(); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		client, instance, err := x.MakeHttpClient(context.Background(), p, 5*time.Second)
		if err != nil {
			t.Fatalf("MakeHttpClient: %v", err)
		}
		defer instance.Close()
		resp, err := client.Get("http://example.com/")
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	code, err := get(t, rightPin)
	if err != nil {
		t.Fatalf("right pin: TLS through xray should succeed, got %v", err)
	}
	if code != http.StatusBadRequest {
		t.Errorf("right pin: status = %d, want 400 from the stand-in server", code)
	}

	if _, err := get(t, wrongPin); err == nil {
		t.Fatalf("wrong pin: expected xray to reject the peer certificate")
	}
}

// allowInsecure must skip certificate checks at runtime on the GFW-knocker
// core: a self-signed server is reached with it and rejected without it.
func TestAllowInsecureSkipsVerificationInXrayCore(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")

	get := func(t *testing.T, insecure string) (int, error) {
		t.Helper()
		x := NewXrayService(false, false)
		p, err := x.CreateProtocol(fmt.Sprintf("trojan://password@%s?security=tls&type=tcp&sni=example.com&fp=chrome&allowInsecure=%s", addr, insecure))
		if err != nil {
			t.Fatalf("CreateProtocol: %v", err)
		}
		if err := p.Parse(); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		client, instance, err := x.MakeHttpClient(context.Background(), p, 5*time.Second)
		if err != nil {
			t.Fatalf("MakeHttpClient: %v", err)
		}
		defer instance.Close()
		resp, err := client.Get("http://example.com/")
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	if code, err := get(t, "1"); err != nil || code != http.StatusBadRequest {
		t.Fatalf("allowInsecure=1: got %d, %v; want 400 from the stand-in server", code, err)
	}
	if _, err := get(t, "0"); err == nil {
		t.Fatalf("allowInsecure=0: expected the self-signed cert to be rejected")
	}
}
