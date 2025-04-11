//go:build !windows

package aws_signing_helper

import (
	"io"
	"os"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

func openTPM() (io.ReadWriteCloser, error) {
	var paths []string
	tpmdev := os.Getenv("TPM_DEVICE")
	if tpmdev != "" {
		paths = append(paths, tpmdev)
	}
	return tpm2.OpenTPM(paths...)
}
