package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, forwarded, proto, wantIP string
		secure                         bool
	}{
		{"HTTP", "", "", "192.0.2.10", false},
		{"proxied HTTP", "198.51.100.4", "http", "198.51.100.4", false},
		{"proxied HTTPS", "198.51.100.4", "https", "198.51.100.4", true},
		{"spoofed prefix", "203.0.113.9, 198.51.100.4", "https", "198.51.100.4", true},
		{"invalid address", "invalid", "https", "192.0.2.10", true},
		{"IPv6", "2001:db8::1", "https", "2001:db8::1", true},
		{"mapped IPv4", "::ffff:198.51.100.4", "https", "198.51.100.4", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://cfg.example/", nil)
			r.RemoteAddr = "192.0.2.10:8000"
			r.Header.Set("X-Forwarded-For", tc.forwarded)
			r.Header.Set("X-Forwarded-Proto", tc.proto)
			if ip, secure := ClientIP(r), IsHTTPS(r); ip != tc.wantIP || secure != tc.secure {
				t.Fatalf("IP=%s HTTPS=%v, want IP=%s HTTPS=%v", ip, secure, tc.wantIP, tc.secure)
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, "https://cfg.example/", nil)
	if !IsHTTPS(r) {
		t.Fatal("direct TLS was not recognized")
	}
	r.Header.Add("X-Forwarded-For", "203.0.113.9")
	r.Header.Add("X-Forwarded-For", "198.51.100.4")
	if ip := ClientIP(r); ip != "198.51.100.4" {
		t.Fatalf("forwarded header lines: IP=%s", ip)
	}
}
