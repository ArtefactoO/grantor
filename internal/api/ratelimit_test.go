package api

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		xff        string
		remoteAddr string
		want       string
	}{
		{"xff first hop", "203.0.113.1, 10.0.0.1, 10.0.0.2", "10.0.0.9:5432", "203.0.113.1"},
		{"xff trimmed", "  203.0.113.7  ", "10.0.0.9:5432", "203.0.113.7"},
		{"xff single", "198.51.100.4", "10.0.0.9:5432", "198.51.100.4"},
		{"no xff uses remote host", "", "192.0.2.5:5432", "192.0.2.5"},
		{"no xff remote without port", "", "192.0.2.5", "192.0.2.5"},
		{"empty xff falls through", "   ", "192.0.2.8:80", "192.0.2.8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}, RemoteAddr: tc.remoteAddr}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(r); got != tc.want {
				t.Errorf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsMutatingMethod(t *testing.T) {
	mutating := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, m := range mutating {
		if !isMutatingMethod(m) {
			t.Errorf("isMutatingMethod(%q) = false, want true", m)
		}
	}
	readOnly := []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	for _, m := range readOnly {
		if isMutatingMethod(m) {
			t.Errorf("isMutatingMethod(%q) = true, want false", m)
		}
	}
}
