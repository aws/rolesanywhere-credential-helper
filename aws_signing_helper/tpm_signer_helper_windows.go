//go:build windows

package aws_signing_helper

import (
	tpm2 "github.com/google/go-tpm/tpm2"
	"io"
)

func openTPM() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
