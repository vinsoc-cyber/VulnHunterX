package main

import "net/http"

var allowedOrigins = map[string]bool{"https://app.example.com": true}

// Reflects a validated origin from an allowlist instead of the wildcard.
func WithCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		handler.ServeHTTP(w, r)
	})
}
