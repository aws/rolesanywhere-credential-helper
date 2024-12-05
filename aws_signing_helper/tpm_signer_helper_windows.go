//go:build windows

package aws_signing_helper

import (
	"io"

	tpm2 "github.com/google/go-tpm/tpm2"
)

func openTPM() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
