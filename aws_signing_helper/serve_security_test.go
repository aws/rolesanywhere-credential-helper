package aws_signing_helper

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestServeRequestGuard(t *testing.T) {
	const tokenPath = "/latest/api/token"
	const credentialsPath = "/latest/meta-data/iam/security-credentials/test-role"
	const port = 9911
	const endpointURL = "http://127.0.0.1:9911"
	var calls atomic.Int32
	handle := func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(tokenPath, handle)
	mux.HandleFunc(credentialsPath, handle)
	guard := serveRequestGuard(port, mux)

	tests := []struct {
		name       string
		method     string
		path       string
		host       string
		origins    []string
		wantStatus int
	}{
		{"SDK token request", http.MethodPut, tokenPath, "", nil, http.StatusOK},
		{"SDK credentials request", http.MethodGet, credentialsPath, "", nil, http.StatusOK},
		{"localhost", http.MethodPut, tokenPath, fmt.Sprintf("localhost:%d", port), nil, http.StatusOK},
		{"same origin", http.MethodPut, tokenPath, "", []string{endpointURL}, http.StatusOK},
		{"rebound token request", http.MethodPut, tokenPath, fmt.Sprintf("attacker.example:%d", port), nil, http.StatusForbidden},
		{"rebound credentials request", http.MethodGet, credentialsPath, fmt.Sprintf("attacker.example:%d", port), nil, http.StatusForbidden},
		{"localhost suffix", http.MethodPut, tokenPath, fmt.Sprintf("localhost.attacker.example:%d", port), nil, http.StatusForbidden},
		{"wrong port", http.MethodPut, tokenPath, "localhost:12345", nil, http.StatusForbidden},
		{"cross origin", http.MethodPut, tokenPath, "", []string{"http://attacker.example:9911"}, http.StatusForbidden},
		{"null origin", http.MethodPut, tokenPath, "", []string{"null"}, http.StatusForbidden},
		{"other loopback port origin", http.MethodPut, tokenPath, "", []string{"http://127.0.0.1:12345"}, http.StatusForbidden},
		{"multiple origins", http.MethodPut, tokenPath, "", []string{endpointURL, "http://attacker.example:9911"}, http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, endpointURL+tc.path, nil)
			if tc.host != "" {
				req.Host = tc.host
			}
			for _, origin := range tc.origins {
				req.Header.Add("Origin", origin)
			}

			before := calls.Load()
			recorder := httptest.NewRecorder()
			guard.ServeHTTP(recorder, req)
			resp := recorder.Result()
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusForbidden && calls.Load() != before {
				t.Error("rejected request reached a metadata handler")
			}
		})
	}
}

func TestServeRequestGuardDefaultPort(t *testing.T) {
	handler := serveRequestGuard(80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, host := range []string{"localhost", LocalHostAddress, "localhost:80", LocalHostAddress + ":80"} {
		t.Run(strings.ReplaceAll(host, ":", "_"), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/latest/api/token", nil)
			req.Host = host
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != http.StatusOK {
				t.Errorf("Host %q: status = %d, want %d", host, resp.Code, http.StatusOK)
			}
		})
	}
}
