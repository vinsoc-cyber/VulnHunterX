package main

import (
	"log"
	"net/http"
)

func h(w http.ResponseWriter, r *http.Request) {
	if err := do(); err != nil {
		log.Println(err)
		http.Error(w, "internal error", 500)
	}
}
