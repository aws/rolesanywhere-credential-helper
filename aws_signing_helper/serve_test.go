//go:build !windows

package aws_signing_helper

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestGracefulShutdown(t *testing.T) {
	// Set up a minimal server using the same pattern as Serve()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: mux}

	// Mirror the signal handling logic from Serve()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	shutdownComplete := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
		close(shutdownComplete)
	}()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(listener)
	}()

	// Verify server is accepting connections
	resp, err := http.Get("http://" + listener.Addr().String() + "/health")
	if err != nil {
		t.Fatal("server not ready:", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Trigger shutdown via signal
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	// Verify server shuts down cleanly
	select {
	case <-shutdownComplete:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not complete within timeout")
	}

	// Serve should return ErrServerClosed
	select {
	case err := <-serveErr:
		if err != http.ErrServerClosed {
			t.Fatalf("expected ErrServerClosed, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestSetupHandlers(t *testing.T) {
	roleName := "roleName"

	mockPutTokenHandler := func(w http.ResponseWriter, r *http.Request) {}
	mockGetRoleNameHandler := func(w http.ResponseWriter, r *http.Request) {}
	mockGetCredentialsHandler := func(w http.ResponseWriter, r *http.Request) {}

	handler := setupHandlers(roleName, mockPutTokenHandler, mockGetRoleNameHandler, mockGetCredentialsHandler)
	server := httptest.NewServer(handler)
	defer server.Close()

	testCases := []struct {
		name   string
		path   string
		method string
	}{
		{"PutTokenHandler without trailing slash", TOKEN_RESOURCE_PATH, "PUT"},
		{"PutTokenHandler with trailing slash", TOKEN_RESOURCE_PATH_WITH_TRAILING_SLASH, "PUT"},
		{"GetRoleNameHandler without trailing slash", SECURITY_CREDENTIALS_RESOURCE_PATH, "GET"},
		{"GetRoleNameHandler with trailing slash", SECURITY_CREDENTIALS_RESOURCE_PATH_WITH_TRAILING_SLASH, "GET"},
		{"GetCredentialsHandler without trailing slash", SECURITY_CREDENTIALS_RESOURCE_PATH_WITH_TRAILING_SLASH + roleName, "GET"},
		{"GetCredentialsHandler with trailing slash", SECURITY_CREDENTIALS_RESOURCE_PATH_WITH_TRAILING_SLASH + roleName + "/", "GET"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if status := resp.StatusCode; status != http.StatusOK {
				t.Errorf("handler for %s returned wrong status code: got %v want %v", tc.path, status, http.StatusOK)
			}
		})
	}
}
