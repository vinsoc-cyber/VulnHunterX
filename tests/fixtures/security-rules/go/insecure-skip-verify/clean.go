package main
import "crypto/tls"
func cfg() *tls.Config { return &tls.Config{InsecureSkipVerify: false} }
