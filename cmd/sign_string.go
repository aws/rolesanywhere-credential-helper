package cmd

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

var (
	format    *enum
	digestArg *enum
)

type enum struct {
	Allowed []string
	Value   string
}

func newEnum(allowed []string, d string) *enum {
	return &enum{
		Allowed: allowed,
		Value:   d,
	}
}

func (e enum) String() string {
	return e.Value
}

func (a *enum) Set(p string) error {
	isIncluded := func(opts []string, val string) bool {
		for _, opt := range opts {
			if val == opt {
				return true
			}
		}
		return false
	}
	if !isIncluded(a.Allowed, p) {
		return fmt.Errorf("%s is not included in %s", p, strings.Join(a.Allowed, ","))
	}
	a.Value = p
	return nil
}

func (a *enum) Type() string {
	return "string"
}

func init() {
	rootCmd.AddCommand(signStringCmd)
	format = newEnum([]string{"json", "text", "bin"}, "json")
	digestArg = newEnum([]string{"SHA256", "SHA384", "SHA512"}, "SHA256")
	signStringCmd.PersistentFlags().StringVar(&certSelector, "cert-selector", "", `JSON structure to identify 
a certificate from a certificate store. Can be passed in either as string or a file name (prefixed by \"file://\")`)
	signStringCmd.PersistentFlags().Var(format, "format", "Output format. One of json, text, and bin")
	signStringCmd.PersistentFlags().Var(digestArg, "digest", "One of SHA256, SHA384, and SHA512")
}

var signStringCmd = &cobra.Command{
	Use:   "sign-string [flags]",
	Short: "Signs a string using the passed-in private key",
	Run: func(cmd *cobra.Command, args []string) {
		certIdentifier, err := PopulateCertIdentifier(certSelector)
		stringToSign, _ := ioutil.ReadAll(bufio.NewReader(os.Stdin))
		var digest crypto.Hash
		switch strings.ToUpper(digestArg.String()) {
		case "SHA256":
			digest = crypto.SHA256
		case "SHA384":
			digest = crypto.SHA384
		case "SHA512":
			digest = crypto.SHA512
		default:
			digest = crypto.SHA256
		}
        var signer crypto.Signer
        if (certIdentifier == helper.CertIdentifier{}) {
            privateKey, _ := helper.ReadPrivateKeyData(privateKeyId)
            signer, _, err = helper.GetFileSystemSigner(privateKey, "", "")
            if err != nil {
                log.Println("unable to create signer with the referenced private key")
                syscall.Exit(1)
            }
        } else {
            signer, _, err = helper.GetCertStoreSigner(certIdentifier)
            if err != nil {
                log.Println("unable to create signer using cert selector")
                syscall.Exit(1)
            }
        }
		sigBytes, err := signer.Sign(rand.Reader, stringToSign, digest)
		if err != nil {
			log.Println("unable to sign the digest")
			syscall.Exit(1)
		}
		sigStr := hex.EncodeToString(sigBytes)
		switch strings.ToLower(format.String()) {
		case "text":
			fmt.Print(sigStr)
		case "json":
			buf, _ := json.Marshal(sigStr)
			fmt.Print(string(buf[:]))
		case "bin":
			binary.Write(os.Stdout, binary.BigEndian, sigBytes[:])
		default:
			fmt.Print(sigStr)
		}
	},
}
