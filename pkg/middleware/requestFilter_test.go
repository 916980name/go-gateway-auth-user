package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	for _, tt := range [...]struct {
		Name       string
		RemoteAddr string
		XFF        string
		XRealIP    string
		Expect     string
	}{
		{
			Name:       "extracts IP from RemoteAddr with port",
			RemoteAddr: "192.168.1.1:8080",
			Expect:     "192.168.1.1",
		},
		{
			Name:       "extracts IP from IPv6 RemoteAddr",
			RemoteAddr: "[::1]:46158",
			Expect:     "[::1]",
		},
		{
			Name:       "ignores X-Forwarded-For header",
			RemoteAddr: "10.0.0.1:1234",
			XFF:        "1.2.3.4, 5.6.7.8",
			Expect:     "10.0.0.1",
		},
		{
			Name:       "ignores X-Real-IP header",
			RemoteAddr: "10.0.0.2:5678",
			XRealIP:    "9.8.7.6",
			Expect:     "10.0.0.2",
		},
		{
			Name:       "ignores both spoofing headers",
			RemoteAddr: "172.16.0.1:80",
			XFF:        "1.1.1.1",
			XRealIP:    "2.2.2.2",
			Expect:     "172.16.0.1",
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.RemoteAddr
			if tt.XFF != "" {
				r.Header.Set("X-Forwarded-For", tt.XFF)
			}
			if tt.XRealIP != "" {
				r.Header.Set("X-Real-IP", tt.XRealIP)
			}
			got := getClientIP(r)
			if got != tt.Expect {
				t.Errorf("getClientIP() = %q, want %q", got, tt.Expect)
			}
		})
	}
}
