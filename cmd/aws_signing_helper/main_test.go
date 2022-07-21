package main

import (
	"testing"
)

func TestParseArgs(t *testing.T) {
	args := []string{
		"read-certificate-data",
		"--certificate",
		"/path/to/cert.pem",
	}
	setupFlags()
	var command = commands[args[0]]
	command.Parse(args[1:])

	if certificateId != "/path/to/cert.pem" {
		t.Errorf("Expected %s, got %s", "/path/to/cert.pem", certificateId)
	}
}
