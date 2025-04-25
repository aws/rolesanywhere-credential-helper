package cmd

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"strings"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

var (
	roleArnStr        string
	profileArnStr     string
	trustAnchorArnStr string
	sessionDuration   int
	region            string
	endpoint          string
	noVerifySSL       bool
	withProxy         bool
	debug             bool
	roleSessionName   string

	certificateId       string
	privateKeyId        string
	certificateBundleId string

	certSelector                 string
	systemStoreName              string
	useLatestExpiringCertificate bool

	libPkcs11 string
	reusePin  bool

	tpmKeyPassword   string
	noTpmKeyPassword bool

	pkcs8Password string

	credentialsOptions helper.CredentialsOpts

	X509_SUBJECT_KEY = "x509Subject"
	X509_ISSUER_KEY  = "x509Issuer"
	X509_SERIAL_KEY  = "x509Serial"

	validCertSelectorKeys = []string{
		X509_SUBJECT_KEY,
		X509_ISSUER_KEY,
		X509_SERIAL_KEY,
	}
)

type MapEntry struct {
	Key   string
	Value string
}

// Parses common flags for commands that vend credentials
func initCredentialsSubCommand(subCmd *cobra.Command) {
	rootCmd.AddCommand(subCmd)
	subCmd.PersistentFlags().StringVar(&roleArnStr, "role-arn", "", "Target role to assume")
	subCmd.PersistentFlags().StringVar(&profileArnStr, "profile-arn", "", "Profile to pull policies from")
	subCmd.PersistentFlags().StringVar(&trustAnchorArnStr, "trust-anchor-arn", "", "Trust anchor to use for authentication")
	subCmd.PersistentFlags().IntVar(&sessionDuration, "session-duration", 3600, "Duration, in seconds, for the resulting session")
	subCmd.PersistentFlags().StringVar(&region, "region", "", "Signing region")
	subCmd.PersistentFlags().StringVar(&endpoint, "endpoint", "", "Endpoint used to call CreateSession")
	subCmd.PersistentFlags().BoolVar(&noVerifySSL, "no-verify-ssl", false, "To disable SSL verification")
	subCmd.PersistentFlags().BoolVar(&withProxy, "with-proxy", false, "To make the CreateSession call with a proxy")
	subCmd.PersistentFlags().BoolVar(&debug, "debug", false, "To print debug output")
	subCmd.PersistentFlags().StringVar(&certificateId, "certificate", "", "Path to certificate file")
	subCmd.PersistentFlags().StringVar(&privateKeyId, "private-key", "", "Path to private key file")
	subCmd.PersistentFlags().StringVar(&certificateBundleId, "intermediates", "", "Path to intermediate certificate bundle file")
	subCmd.PersistentFlags().StringVar(&certSelector, "cert-selector", "", "JSON structure to identify a certificate from a certificate store. "+
		"Can be passed in either as string or a file name (prefixed by \"file://\")")
	subCmd.PersistentFlags().StringVar(&systemStoreName, "system-store-name", "MY", "Name of the system store to search for within the "+
		"CERT_SYSTEM_STORE_CURRENT_USER context. Note that this flag is only relevant for Windows certificate stores and will be ignored otherwise")
	subCmd.PersistentFlags().BoolVar(&useLatestExpiringCertificate, "use-latest-expiring-certificate", false, "If multiple certificates match "+
		"a given certificate selector, the one that expires the latest will be chosen (if more than one still fits this criteria, an arbitrary "+
		"one is chosen from those that meet the criteria)")
	subCmd.PersistentFlags().StringVar(&libPkcs11, "pkcs11-lib", "", "Library for smart card / cryptographic device (OpenSC or vendor specific)")
	subCmd.PersistentFlags().BoolVar(&reusePin, "reuse-pin", false, "Use the CKU_USER PIN as the CKU_CONTEXT_SPECIFIC PIN for "+
		"private key objects, when they are first used to sign. If the CKU_USER PIN doesn't work as the CKU_CONTEXT_SPECIFIC PIN "+
		"for a given private key object, fall back to prompting the user")
	subCmd.PersistentFlags().StringVar(&tpmKeyPassword, "tpm-key-password", "", "Password for TPM key, if applicable")
	subCmd.PersistentFlags().BoolVar(&noTpmKeyPassword, "no-tpm-key-password", false, "Required if the TPM key has no password and"+
		"a handle is used to refer to the key")
	subCmd.PersistentFlags().StringVar(&roleSessionName, "role-session-name", "", "An identifier of a role session")
	subCmd.PersistentFlags().StringVar(&pkcs8Password, "pkcs8-password", "", "Password for PKCS#8 key, if applicable")

	subCmd.MarkFlagsMutuallyExclusive("certificate", "cert-selector")
	subCmd.MarkFlagsMutuallyExclusive("certificate", "system-store-name")
	subCmd.MarkFlagsMutuallyExclusive("private-key", "cert-selector")
	subCmd.MarkFlagsMutuallyExclusive("private-key", "system-store-name")
	subCmd.MarkFlagsMutuallyExclusive("private-key", "use-latest-expiring-certificate")
	subCmd.MarkFlagsMutuallyExclusive("use-latest-expiring-certificate", "intermediates")
	subCmd.MarkFlagsMutuallyExclusive("use-latest-expiring-certificate", "reuse-pin")
	subCmd.MarkFlagsMutuallyExclusive("cert-selector", "intermediates")
	subCmd.MarkFlagsMutuallyExclusive("cert-selector", "reuse-pin")
	subCmd.MarkFlagsMutuallyExclusive("system-store-name", "reuse-pin")
	subCmd.MarkFlagsMutuallyExclusive("tpm-key-password", "cert-selector")
	subCmd.MarkFlagsMutuallyExclusive("tpm-key-password", "reuse-pin")
	subCmd.MarkFlagsMutuallyExclusive("no-tpm-key-password", "cert-selector")
	subCmd.MarkFlagsMutuallyExclusive("no-tpm-key-password", "tpm-key-password")
	subCmd.MarkFlagsMutuallyExclusive("pkcs8-password", "tpm-key-password")
}

// Parses a cert selector string to a map
func getStringMap(s string) (map[string]string, error) {
	entries := strings.Split(s, " ")

	m := make(map[string]string)
	for _, e := range entries {
		tokens := strings.SplitN(e, ",", 2)
		keyTokens := strings.Split(tokens[0], "=")
		if keyTokens[0] != "Key" {
			return nil, errors.New("invalid cert selector map key")
		}
		key := strings.TrimSpace(strings.Join(keyTokens[1:], "="))

		isValidKey := false
		for _, validKey := range validCertSelectorKeys {
			if validKey == key {
				isValidKey = true
				break
			}
		}
		if !isValidKey {
			return nil, errors.New("cert selector contained invalid key")
		}

		valueTokens := strings.Split(tokens[1], "=")
		if valueTokens[0] != "Value" {
			return nil, errors.New("invalid cert selector map value")
		}
		value := strings.TrimSpace(strings.Join(valueTokens[1:], "="))
		m[key] = value
	}

	return m, nil
}

// Parses a JSON cert selector string into a map
func getMapFromJsonEntries(jsonStr string) (map[string]string, error) {
	m := make(map[string]string)
	var mapEntries []MapEntry
	err := json.Unmarshal([]byte(jsonStr), &mapEntries)
	if err != nil {
		return nil, errors.New("unable to parse JSON map entries")
	}
	for _, mapEntry := range mapEntries {
		isValidKey := false
		for _, validKey := range validCertSelectorKeys {
			if validKey == mapEntry.Key {
				isValidKey = true
				break
			}
		}
		if !isValidKey {
			return nil, errors.New("cert selector contained invalid key")
		}
		m[mapEntry.Key] = mapEntry.Value
	}
	return m, nil
}

func createCertSelectorFromMap(certSelectorMap map[string]string) helper.CertIdentifier {
	var certIdentifier helper.CertIdentifier

	for key, value := range certSelectorMap {
		switch key {
		case X509_SUBJECT_KEY:
			certIdentifier.Subject = value
		case X509_ISSUER_KEY:
			certIdentifier.Issuer = value
		case X509_SERIAL_KEY:
			certSerial := new(big.Int)
			certSerial.SetString(value, 16)
			certIdentifier.SerialNumber = certSerial
		}
	}

	return certIdentifier
}

func PopulateCertIdentifierFromJsonStr(jsonStr string) (helper.CertIdentifier, error) {
	certSelectorMap, err := getMapFromJsonEntries(jsonStr)
	if err != nil {
		return helper.CertIdentifier{}, err
	}
	return createCertSelectorFromMap(certSelectorMap), nil
}

// Populates a CertIdentifier object using a cert selector string
func PopulateCertIdentifierFromCertSelectorStr(certSelectorStr string) (helper.CertIdentifier, error) {
	certSelectorMap, err := getStringMap(certSelectorStr)
	if err != nil {
		return helper.CertIdentifier{}, err
	}

	return createCertSelectorFromMap(certSelectorMap), nil
}

// Populates a CertIdentifier using a cert selector
// Note that this method can take in a file name as a the cert selector
func PopulateCertIdentifier(certSelector string, systemStoreName string) (helper.CertIdentifier, error) {
	var (
		certIdentifier helper.CertIdentifier
		err            error
	)

	if certSelector != "" {
		if strings.HasPrefix(certSelector, "file://") {
			certSelectorFile, err := ioutil.ReadFile(strings.TrimPrefix(certSelector, "file://"))
			if err != nil {
				return helper.CertIdentifier{}, errors.New("unable to read cert selector file")
			}
			certIdentifier, err = PopulateCertIdentifierFromJsonStr(string(certSelectorFile[:]))
			if err != nil {
				return helper.CertIdentifier{}, errors.New("unable to parse JSON cert selector")
			}
		} else {
			certIdentifier, err = PopulateCertIdentifierFromCertSelectorStr(certSelector)
			if err != nil {
				return helper.CertIdentifier{}, errors.New("unable to parse cert selector string")
			}
		}
	}
	matchedPredefinedSystemStoreName := false
	for _, predefinedSystemStoreName := range helper.SystemStoreNames {
		if strings.EqualFold(systemStoreName, predefinedSystemStoreName) {
			certIdentifier.SystemStoreName = predefinedSystemStoreName
			matchedPredefinedSystemStoreName = true
			break
		}
	}
	if !matchedPredefinedSystemStoreName {
		certIdentifier.SystemStoreName = systemStoreName
	}

	return certIdentifier, err
}

// Populate CredentialsOpts that is used to aggregate all the information required to call CreateSession
func PopulateCredentialsOptions() error {
	certIdentifier, err := PopulateCertIdentifier(certSelector, systemStoreName)
	if err != nil {
		return err
	}

	credentialsOptions = helper.CredentialsOpts{
		PrivateKeyId:                 privateKeyId,
		CertificateId:                certificateId,
		CertificateBundleId:          certificateBundleId,
		CertIdentifier:               certIdentifier,
		UseLatestExpiringCertificate: useLatestExpiringCertificate,
		RoleArn:                      roleArnStr,
		ProfileArnStr:                profileArnStr,
		TrustAnchorArnStr:            trustAnchorArnStr,
		SessionDuration:              sessionDuration,
		Region:                       region,
		Endpoint:                     endpoint,
		NoVerifySSL:                  noVerifySSL,
		WithProxy:                    withProxy,
		Debug:                        debug,
		Version:                      Version,
		LibPkcs11:                    libPkcs11,
		ReusePin:                     reusePin,
		TpmKeyPassword:               tpmKeyPassword,
		NoTpmKeyPassword:             noTpmKeyPassword,
		RoleSessionName:              roleSessionName,
		Pkcs8Password:                pkcs8Password,
	}

	return nil
}
