package convert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// TestMasqueExports: masque is exported to xray JSON as a masque outbound
// and skipped by formats that have no masque (Clash, sing-box).
func TestMasqueExports(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	links := []string{
		"masque://" + url.QueryEscape(base64.StdEncoding.EncodeToString(der)) + "@162.159.198.1:443?transport=h3#mq1",
		"vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?security=tls&type=ws&sni=a.com#v1",
	}

	out, r, err := ToXray(links)
	if err != nil || r.Converted != 2 || !strings.Contains(string(out), `"protocol": "masque"`) {
		t.Errorf("xray export: err=%v report=%+v\n%s", err, r, out)
	}

	clash := func() ([]byte, *Report, error) { return ToClash(links, ClashOptions{}) }
	singbox := func() ([]byte, *Report, error) { return ToSingbox(links, SingboxOptions{}) }
	for name, export := range map[string]func() ([]byte, *Report, error){"clash": clash, "sing-box": singbox} {
		out, r, err := export()
		if err != nil {
			t.Fatalf("%s export: %v", name, err)
		}
		if r.Converted != 1 || len(r.Skipped) != 1 || r.Skipped[0].Index != 0 {
			t.Errorf("%s export: report=%+v, want only the masque link skipped", name, r)
		}
		if strings.Contains(string(out), "mq1") {
			t.Errorf("%s export contains the masque link:\n%s", name, out)
		}
	}
}
