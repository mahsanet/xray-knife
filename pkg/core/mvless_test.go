package core

import (
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
)

// TestAutomaticCoreRoutesMVlessToXray: only the GFW-knocker xray core runs
// mvless.
func TestAutomaticCoreRoutesMVlessToXray(t *testing.T) {
	c := NewAutomaticCoreWith(FactoryOptions{InsecureTLS: true}).(*AutomaticCore)
	p, err := c.CreateProtocol("mvless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&type=ws&sni=a.com")
	if err != nil {
		t.Fatal(err)
	}
	if name := p.ConvertToGeneralConfig().Protocol; name != "mvless" {
		t.Fatalf("created %s, want mvless", name)
	}
	if _, ok := p.(xray.Protocol); !ok {
		t.Fatalf("created %T, want the xray core", p)
	}
}
