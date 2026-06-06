package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
)

// Key loaded from the environment, not embedded in source.
func calculateRefundSecureHash(message string) string {
	key := []byte(os.Getenv("REFUND_SIGNING_KEY"))
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
