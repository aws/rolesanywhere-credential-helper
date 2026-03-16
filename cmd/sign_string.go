package cmd

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

var (
	format    *enum
	digestArg *enum
)

var (
	SIGN_STRING_TEST_VERSION uint16 = 1
	signFixedString          bool   = true
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
	signStringCmd.PersistentFlags().StringVar(&certificateId, "certificate", "", "PKCS#11 URI to identify the certificate")
	signStringCmd.PersistentFlags().StringVar(&privateKeyId, "private-key", "", "Path to private key file or PKCS#11 URI to identify the private key")
	signStringCmd.PersistentFlags().BoolVar(&debug, "debug", false, "To print debug output")
	signStringCmd.PersistentFlags().StringVar(&certSelector, "cert-selector", "", "JSON structure to identify a certificate from a certificate store. "+
		"Can be passed in either as string or a file name (prefixed by \"file://\")")
	signStringCmd.PersistentFlags().StringVar(&systemStoreName, "system-store-name", "MY", "Name of the system store to search for. "+
		"Note that this flag is only relevant for Windows certificate stores and will be ignored otherwise")
	signStringCmd.PersistentFlags().StringVar(&systemStoreLocation, "system-store-location", "CurrentUser", "Location of the system store to search for. "+
		"Can be either \"CurrentUser\" or \"LocalMachine\". Note that this flag is only relevant for Windows certificate stores and will be ignored otherwise")
	signStringCmd.PersistentFlags().BoolVar(&useLatestExpiringCertificate, "use-latest-expiring-certificate", false, "If multiple certificates match "+
		"a given certificate selector, the one that expires the latest will be chosen (if more than one still fits this criteria, an arbitrary "+
		"one is chosen from those that meet the criteria)")
	signStringCmd.PersistentFlags().StringVar(&libPkcs11, "pkcs11-lib", "", "Library for smart card / cryptographic device (default: p11-kit-proxy.{so, dll, dylib})")
	signStringCmd.PersistentFlags().BoolVar(&reusePin, "reuse-pin", false, "Use the CKU_USER PIN as the CKU_CONTEXT_SPECIFIC PIN for "+
		"private key objects, when they are first used to sign. If the CKU_USER PIN doesn't work as the CKU_CONTEXT_SPECIFIC PIN "+
		"for a given private key object, fall back to prompting the user")
	signStringCmd.PersistentFlags().StringVar(&tpmKeyPassword, "tpm-key-password", "", "Password for TPM key, if applicable")
	signStringCmd.PersistentFlags().BoolVar(&noTpmKeyPassword, "no-tpm-key-password", false, "Required if the TPM key has no password and"+
		"a handle is used to refer to the key")
	signStringCmd.PersistentFlags().Var(format, "format", "Output format. One of json, text, and bin")
	signStringCmd.PersistentFlags().Var(digestArg, "digest", "One of SHA256, SHA384, and SHA512")
	signStringCmd.PersistentFlags().StringVar(&pkcs8Password, "pkcs8-password", "", "Password for PKCS#8 key, if applicable")

	signStringCmd.MarkFlagsMutuallyExclusive("certificate", "cert-selector")
	signStringCmd.MarkFlagsMutuallyExclusive("certificate", "system-store-name")
	signStringCmd.MarkFlagsMutuallyExclusive("certificate", "system-store-location")
	signStringCmd.MarkFlagsMutuallyExclusive("private-key", "cert-selector")
	signStringCmd.MarkFlagsMutuallyExclusive("private-key", "system-store-name")
	signStringCmd.MarkFlagsMutuallyExclusive("private-key", "system-store-location")
	signStringCmd.MarkFlagsMutuallyExclusive("private-key", "use-latest-expiring-certificate")
	signStringCmd.MarkFlagsMutuallyExclusive("use-latest-expiring-certificate", "reuse-pin")
	signStringCmd.MarkFlagsMutuallyExclusive("cert-selector", "reuse-pin")
	signStringCmd.MarkFlagsMutuallyExclusive("system-store-name", "reuse-pin")
	signStringCmd.MarkFlagsMutuallyExclusive("system-store-location", "reuse-pin")
	signStringCmd.MarkFlagsMutuallyExclusive("tpm-key-password", "cert-selector")
	signStringCmd.MarkFlagsMutuallyExclusive("tpm-key-password", "reuse-pin")
	signStringCmd.MarkFlagsMutuallyExclusive("no-tpm-key-password", "cert-selector")
	signStringCmd.MarkFlagsMutuallyExclusive("no-tpm-key-password", "reuse-pin")
	signStringCmd.MarkFlagsMutuallyExclusive("no-tpm-key-password", "tpm-key-password")
	signStringCmd.MarkFlagsMutuallyExclusive("pkcs8-password", "tpm-key-password")
}

func getFixedStringToSign(publicKey crypto.PublicKey) string {
	var digestSuffix []byte
	ecdsaPublicKey, isEcKey := publicKey.(*ecdsa.PublicKey)
	if isEcKey {
		digestSuffixArr := sha256.Sum256(append([]byte("IAM RA"), elliptic.Marshal(ecdsaPublicKey, ecdsaPublicKey.X, ecdsaPublicKey.Y)...))
		digestSuffix = digestSuffixArr[:]
	}

	rsaPublicKey, isRsaKey := publicKey.(*rsa.PublicKey)
	if isRsaKey {
		digestSuffixArr := sha256.Sum256(append([]byte("IAM RA"), x509.MarshalPKCS1PublicKey(rsaPublicKey)...))
		digestSuffix = digestSuffixArr[:]
	}

	// "AWS Roles Anywhere Credential Helper Signing Test" || SIGN_STRING_TEST_VERSION ||
	// SHA256("IAM RA" || PUBLIC_KEY_BYTE_ARRAY)
	fixedStringToSign := "AWS Roles Anywhere Credential Helper Signing Test" +
		strconv.Itoa(int(SIGN_STRING_TEST_VERSION)) + string(digestSuffix)

	return fixedStringToSign
}

var signStringCmd = &cobra.Command{
	Use:   "sign-string [flags]",
	Short: "Signs a fixed string using the passed-in private key (or reference to private key)",
	Run: func(cmd *cobra.Command, args []string) {
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
		err := PopulateCredentialsOptions()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		helper.Debug = credentialsOptions.Debug

		var signer helper.Signer
		signer, _, err = helper.GetSigner(&credentialsOptions)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		defer signer.Close()

		var stringToSignBytes []byte
		if signFixedString {
			stringToSign := getFixedStringToSign(signer.Public())
			stringToSignBytes = []byte(stringToSign)

			if credentialsOptions.Debug {
				log.Println("Signing fixed string of the form: \"AWS Roles Anywhere " +
					"Credential Helper Signing Test\" || SIGN_STRING_TEST_VERSION || SHA256(\"IAM RA\" || PUBLIC_KEY_BYTE_ARRAY)\"")
			}
		} else {
			stringToSignBytes, _ = ioutil.ReadAll(bufio.NewReader(os.Stdin))
		}

		sigBytes, err := signer.Sign(rand.Reader, stringToSignBytes, digest)
		if err != nil {
			log.Println("unable to sign the digest:", err)
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
