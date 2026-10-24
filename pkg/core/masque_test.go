package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
)

func masqueKey(t *testing.T) string {
	t.Helper()
	for range 200 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		// Prefer a key with both characters a raw link leaves unescaped.
		if b := base64.StdEncoding.EncodeToString(der); strings.Contains(b, "/") && strings.Contains(b, "+") {
			return b
		}
	}
	t.Fatal("no key with / and +")
	return ""
}

// TestAutomaticCoreRoutesMasqueToXray: only the GFW-knocker xray core runs
// masque.
func TestAutomaticCoreRoutesMasqueToXray(t *testing.T) {
	c := NewAutomaticCoreWith(FactoryOptions{}).(*AutomaticCore)
	p, err := c.CreateProtocol("MASQUE://" + url.QueryEscape(masqueKey(t)) + "@162.159.198.1:443?transport=h3")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Parse(); err != nil {
		t.Fatal(err)
	}
	if name := p.ConvertToGeneralConfig().Protocol; name != "masque" {
		t.Fatalf("created %s, want masque", name)
	}
	if _, ok := p.(*xray.Masque); !ok {
		t.Fatalf("created %T, want the xray core", p)
	}
}

// TestConnectionFingerprintMasque: raw and percent-encoded keys and a
// changed remark are the same connection; another key or carrier is not.
func TestConnectionFingerprintMasque(t *testing.T) {
	c := NewAutomaticCoreWith(FactoryOptions{})
	key := masqueKey(t)
	fp := func(link string) string {
		t.Helper()
		got, err := ConnectionFingerprint(c, link)
		if err != nil {
			t.Fatalf("ConnectionFingerprint(%q): %v", link, err)
		}
		return got
	}
	raw := fp("masque://" + key + "@162.159.198.1:443?transport=h3#a")
	if enc := fp("masque://" + url.QueryEscape(key) + "@162.159.198.1:443?transport=h3#b"); enc != raw {
		t.Error("raw and encoded keys fingerprint differently")
	}
	if other := fp("masque://" + url.QueryEscape(masqueKey(t)) + "@162.159.198.1:443?transport=h3"); other == raw {
		t.Error("different keys share a fingerprint")
	}
	if h2 := fp("masque://" + key + "@162.159.198.1:443?transport=h2"); h2 == raw {
		t.Error("h2 and h3 share a fingerprint")
	}
}
