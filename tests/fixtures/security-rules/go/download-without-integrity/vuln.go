package main

import "os/exec"

func install() error {
	return exec.Command("sh", "-c", "curl https://example.com/i.sh | sh").Run()
}
