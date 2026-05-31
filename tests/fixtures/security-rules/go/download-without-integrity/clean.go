package main

import "os/exec"

func install() error {
	return exec.Command("apt-get", "install", "-y", "curl").Run()
}
