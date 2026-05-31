package main
import "crypto/sha256"
func Hash(data []byte) [32]byte { return sha256.Sum256(data) }
