package main
import "os"
func save(data []byte) error { return os.WriteFile("/tmp/x", data, 0o600) }
