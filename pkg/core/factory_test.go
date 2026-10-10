package core

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v10/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v10/pkg/core/xray"
)

// xray-core dropped the shadowsocks "none"/"plain" ciphers, so the automatic
// core must run them on sing-box and keep the rest on xray.
func TestAutomaticCoreShadowsocksCiphers(t *testing.T) {
	c := NewAutomaticCore(false, false)
	for method, wantSingbox := range map[string]bool{"none": true, "plain": true, "aes-128-gcm": false} {
		link := "ss://" + base64.StdEncoding.EncodeToString([]byte(method+":pw")) + "@1.2.3.4:8388#ss"
		p, err := c.CreateProtocol(link)
		if err != nil {
			t.Fatal(err)
		}
		_, onSingbox := p.(singbox.Protocol)
		_, onXray := p.(xray.Protocol)
		if onSingbox != wantSingbox || onXray == wantSingbox {
			t.Fatalf("%s: got %T", method, p)
		}
		if err := p.Parse(); err != nil {
			t.Fatal(err)
		}
		_, inst, err := c.MakeHttpClient(context.Background(), p, time.Second)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		inst.Close()
	}
}
