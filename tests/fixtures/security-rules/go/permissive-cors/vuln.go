package main

import "net/http"

// Mirrors the real FN in 1192-services: wildcard CORS on every response.
func WithCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		handler.ServeHTTP(w, r)
	})
}
