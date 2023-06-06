package cmd

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

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
	signStringCmd.PersistentFlags().StringVar(&certificateId, "certificate", "", "Path to certificate file")
	signStringCmd.PersistentFlags().StringVar(&certSelector, "cert-selector", "", `JSON structure to identify
a certificate from a certificate store. Can be passed in either as string or a file name (prefixed by \"file://\")`)
	signStringCmd.PersistentFlags().StringVar(&privateKeyId, "private-key", "", "Path to private key file")
	signStringCmd.PersistentFlags().StringVar(&libPkcs11, "pkcs11-lib", "", "Library for smart card / cryptographic device (default: p11-kit-proxy.so)")
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
		if privateKeyId != "" && !strings.HasPrefix(privateKeyId, "pkcs11:") {
			privateKey, _ := helper.ReadPrivateKeyData(privateKeyId)
			signer, _, err = helper.GetFileSystemSigner(privateKey)
			if err != nil {
				log.Println("unable to create signer with the referenced private key")
				os.Exit(1)
			}
		} else if strings.HasPrefix(privateKeyId, "pkcs11:") ||
			(privateKeyId == "" && strings.HasPrefix(certificateId, "pkcs11:")) {
			var certificate *x509.Certificate
			if certificateId != "" && !strings.HasPrefix(certificateId, "pkcs11:") {
				certificates, err := helper.ReadCertificateBundleData(certificateId)

				if err != nil {
					log.Println("unable to read certificate")
					os.Exit(1)
				}
				certificate = certificates[0]
			}

			signer, _, err = helper.GetPKCS11Signer(certIdentifier, libPkcs11, certificate, nil, privateKeyId, certificateId)
		} else {
			signer, _, err = helper.GetCertStoreSigner(certIdentifier)
			if err != nil {
				log.Println("unable to create signer using cert selector")
				os.Exit(1)
			}
		}
		if err != nil {
		   log.Println(err)
		   os.Exit(1)
		}
		sigBytes, err := signer.Sign(rand.Reader, stringToSign, digest)
		if err != nil {
			log.Println("unable to sign the digest")
			os.Exit(1)
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
