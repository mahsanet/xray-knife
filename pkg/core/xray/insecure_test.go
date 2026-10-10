package xray

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// allowInsecure must skip certificate checks at runtime on the GFW-knocker
// core: a self-signed server is reached with it and rejected without it.
// The server isn't trojan, so a reached server answers 400.
func TestAllowInsecureSkipsVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")

	get := func(insecure string) (int, error) {
		x := NewXrayService(false, false)
		p, err := x.CreateProtocol(fmt.Sprintf("trojan://password@%s?security=tls&type=tcp&sni=example.com&fp=chrome&allowInsecure=%s", addr, insecure))
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Parse(); err != nil {
			t.Fatal(err)
		}
		client, instance, err := x.MakeHttpClient(context.Background(), p, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer instance.Close()
		resp, err := client.Get("http://example.com/")
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	if code, err := get("1"); err != nil || code != http.StatusBadRequest {
		t.Fatalf("allowInsecure=1: got %d, %v; want 400", code, err)
	}
	if _, err := get("0"); err == nil {
		t.Fatal("allowInsecure=0: expected the self-signed cert to be rejected")
	}
}
