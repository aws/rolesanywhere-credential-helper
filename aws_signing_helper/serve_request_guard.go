package aws_signing_helper

import (
	"fmt"
	"net/http"
	"strings"
)

const LocalHostAddress = "127.0.0.1"

// serveRequestGuard prevents a browser from reaching the loopback listener
func serveRequestGuard(port int, next http.Handler) http.Handler {
	loopbackHost := fmt.Sprintf("%s:%d", LocalHostAddress, port)
	localhostHost := fmt.Sprintf("localhost:%d", port)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostAllowed := r.Host == loopbackHost || strings.EqualFold(r.Host, localhostHost)
		if port == 80 {
			hostAllowed = hostAllowed || r.Host == LocalHostAddress || strings.EqualFold(r.Host, "localhost")
		}
		if !hostAllowed {
			http.Error(w, "invalid Host header", http.StatusForbidden)
			return
		}

		// SDK clients omit Origin. When present, it must identify this same
		// endpoint; a browser making a rebound request uses the attacker's origin.
		origins := r.Header.Values("Origin")
		if len(origins) > 0 && (len(origins) != 1 || !strings.EqualFold(origins[0], "http://"+r.Host)) {
			http.Error(w, "invalid Origin header", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
