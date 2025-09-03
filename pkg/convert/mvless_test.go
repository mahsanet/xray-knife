package convert

import (
	"strings"
	"testing"
)

// TestMVlessExports: mvless is exported to xray JSON as an mvless outbound
// and skipped by formats that have no mvless (Clash, sing-box), not
// exported as plain VLESS.
func TestMVlessExports(t *testing.T) {
	const id = "a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5"
	links := []string{
		"mvless://" + id + "@1.2.3.4:443?security=tls&type=ws&sni=a.com#m1",
		"vless://" + id + "@1.2.3.4:443?security=tls&type=ws&sni=a.com#v1",
	}

	out, r, err := ToXray(links)
	if err != nil || r.Converted != 2 || !strings.Contains(string(out), `"protocol": "mvless"`) {
		t.Errorf("xray export: err=%v report=%+v\n%s", err, r, out)
	}

	clash := func() ([]byte, *Report, error) { return ToClash(links, ClashOptions{}) }
	singbox := func() ([]byte, *Report, error) { return ToSingbox(links, SingboxOptions{}) }
	for name, export := range map[string]func() ([]byte, *Report, error){"clash": clash, "sing-box": singbox} {
		out, r, err := export()
		if err != nil {
			t.Fatalf("%s export: %v", name, err)
		}
		if r.Converted != 1 || len(r.Skipped) != 1 || r.Skipped[0].Index != 0 || !strings.Contains(r.Skipped[0].Reason, "mvless") {
			t.Errorf("%s export: report=%+v, want only the mvless link skipped", name, r)
		}
		if strings.Contains(string(out), "m1") {
			t.Errorf("%s export contains the mvless link:\n%s", name, out)
		}
	}
}
