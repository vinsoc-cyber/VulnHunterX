package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Mirrors the real FN in 1192-services: a placeholder HMAC key left in a
// production signing path. Anyone reading the source can forge signatures.
func calculateRefundSecureHash(transactionID, transRefID, merchantID string) string {
	message := transactionID + transRefID + merchantID
	h := hmac.New(sha256.New, []byte("mock-secret-key"))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
