package main

import "net/http"

func h(w http.ResponseWriter, r *http.Request) {
	if err := do(); err != nil {
		http.Error(w, err.Error(), 500)
	}
}
