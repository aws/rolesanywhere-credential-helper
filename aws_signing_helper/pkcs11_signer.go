package aws_signing_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"log"
	"unsafe"
	
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
	"github.com/miekg/pkcs11"
	"golang.org/x/term"
)

var PKCS11_TEST_VERSION int16 = 1
var MAX_OBJECT_LIMIT int = 1000

type PKCS11Signer struct {
	cert             *x509.Certificate
	certChain        []*x509.Certificate
	module           *pkcs11.Ctx
	session          pkcs11.SessionHandle
	privateKeyHandle pkcs11.ObjectHandle
	pin              string
	keyType		 uint
}

// Helper function to check whether the passed in []uint contains a given element
func contains(slice []uint, find uint) bool {
	for _, v := range slice {
		if v == find {
			return true
		}
	}

	return false
}

type SlotIdInfo struct {
	id	uint
	info	pkcs11.SlotInfo
	tokinfo pkcs11.TokenInfo
}

// Return true if the URI specifies the attribute and it *doesn't* match
func mismatchAttr(uri *pkcs11uri.Pkcs11URI, attr string, val string) (res bool) {
	var urival string
	var ok bool

	urival, ok = uri.GetPathAttribute(attr, false)
	if ok && urival != val {
		return true
	}

	return false
}

func matchSlots(slots []SlotIdInfo, uri *pkcs11uri.Pkcs11URI) (matches []SlotIdInfo) {

	if uri == nil {
		return slots
	}

	var urislotnr uint64
	var urislot string
	var ok bool

	urislot, ok = uri.GetPathAttribute("slot-id", false)
	if ok {
		urislotnr, _ = strconv.ParseUint(urislot, 0, 32)
	}

	for _, slot := range slots {
		if urislotnr != 0 && urislotnr != uint64(slot.id) {
			continue
		}
		if mismatchAttr(uri, "token", slot.tokinfo.Label) ||
		   mismatchAttr(uri, "model", slot.tokinfo.Model) ||
		   mismatchAttr(uri, "manufacturer", slot.tokinfo.ManufacturerID) ||
		   mismatchAttr(uri, "serial", slot.tokinfo.SerialNumber) ||
   		   mismatchAttr(uri, "slot-description", slot.info.SlotDescription) ||
   		   mismatchAttr(uri, "slot-manufacturer", slot.info.ManufacturerID) {
			continue
		}
		matches = append(matches, slot)
	}

	return matches
}

// Initialize and enumerate slots in the PKCS#11 module
func openPKCS11Module(lib string) (module *pkcs11.Ctx, slots []SlotIdInfo, err error) {
	var slot_ids []uint

	// In a properly configured system, nobody should need to override this.
	if lib == "" {
		lib = "p11-kit-proxy.so"
	}

	module = pkcs11.New(lib)
	if module == nil {
		err = errors.New("Failed to load provider library " + lib)
		goto fail
	}
	if err = module.Initialize(); err != nil {
		goto fail
	}

	slot_ids, err = module.GetSlotList(true)
	if err != nil {
		goto fail
	}

	for _, slotid := range slot_ids {
		var slotidinfo SlotIdInfo
		var slot_err error

		slotidinfo.id = slotid
		slotidinfo.info, slot_err = module.GetSlotInfo(slotid)
		if (slot_err != nil) {
			continue
		}
		slotidinfo.tokinfo, slot_err = module.GetTokenInfo(slotid)
		if (slot_err != nil) {
			continue
		}

		slots = append(slots, slotidinfo)

	}

	return module, slots, nil

fail:
	if module != nil {
		module.Finalize()
		module.Destroy()
	}
	return nil, nil, err
}

// Opens a session with the PKCS #11 module
func openPKCS11Session(lib string, slot uint, uri *pkcs11uri.Pkcs11URI) (module *pkcs11.Ctx, session pkcs11.SessionHandle, err error) {

	module, _, err = openPKCS11Module(lib)
	if err != nil {
		goto fail
	}

	session, err = module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
	if err != nil {
		goto fail
	}
	log.Println("Got session")
	return module, session, nil

fail:
	if module != nil {
		if session != 0 {
			module.CloseSession(session)
		}
		module.Finalize()
		module.Destroy()
	}
	return nil, 0, err
}

func getFindTemplate(uri *pkcs11uri.Pkcs11URI, class uint) (template []*pkcs11.Attribute) {
	var v string
	var ok bool

	template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, class))

	if uri == nil {
		return template
	}

	v, ok = uri.GetPathAttribute("object", false)
	if ok {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, v))
	}
	v, ok = uri.GetPathAttribute("id", false)
	if ok {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, v))
	}
	return template
}

type CertObjInfo struct {
	id	[]byte
	label	[]byte
	x509	*x509.Certificate
}

// Gets all certificates within the PKCS #11 session
func getCerts(module *pkcs11.Ctx, session pkcs11.SessionHandle, uri *pkcs11uri.Pkcs11URI, certIdentifier CertIdentifier, single bool) (certs []CertObjInfo, err error) {
	var sessionCertObjects []pkcs11.ObjectHandle
	var certObjects []pkcs11.ObjectHandle
	var templateCrt []*pkcs11.Attribute

	// Finds certificates within the cryptographic device
	templateCrt = getFindTemplate(uri, pkcs11.CKO_CERTIFICATE)

	if err = module.FindObjectsInit(session, templateCrt); err != nil {
		return nil, err
	}

	for true {
		sessionCertObjects, _, err = module.FindObjects(session, MAX_OBJECT_LIMIT)
		if err != nil {
			return nil, err
		}
		if len(sessionCertObjects) == 0 {
			break
		}
		certObjects = append(certObjects, sessionCertObjects...)
	}

	err = module.FindObjectsFinal(session)
	if err != nil {
		return nil, err
	}

	for _, certObject := range certObjects {
		crtAttributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
		}
		if crtAttributes, err = module.GetAttributeValue(session, certObject, crtAttributes); err != nil {
			return nil, err
		}

		rawCert := crtAttributes[0].Value

		var cert_obj CertObjInfo

		cert_obj.x509, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, errors.New("error parsing certificate")
		}

		if certMatches(certIdentifier, *cert_obj.x509) {
			crtAttributes[0] = pkcs11.NewAttribute(pkcs11.CKA_ID, 0)
			crtAttributes, err = module.GetAttributeValue(session, certObject, crtAttributes)
			if err == nil {
				cert_obj.id = crtAttributes[0].Value
			}

			crtAttributes[0] = pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0)
			crtAttributes, err = module.GetAttributeValue(session, certObject, crtAttributes)
			if err == nil {
				cert_obj.label = crtAttributes[0].Value
			}

			certs = append(certs, cert_obj)
		}
	}

	return certs, nil
}

// Gets certificates that match the passed in CertIdentifier
func getMatchingCerts(module *pkcs11.Ctx, slots []SlotIdInfo, certIdentifier CertIdentifier, uri *pkcs11uri.Pkcs11URI, single bool, pinPkcs11 *string) (session pkcs11.SessionHandle, slot_nr uint, logged_in bool, matchingCerts []CertObjInfo, err error) {
	if uri != nil {
		slots = matchSlots(slots, uri)
	}

	for _, slot := range slots {
		session, err = module.OpenSession(slot.id, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
		if err != nil {
			continue
		}

		matchingCerts, err = getCerts(module, session, uri, certIdentifier, single)
		if err == nil && len(matchingCerts) > 0 {
			return session, slot.id, false, matchingCerts, nil
		}
		module.CloseSession(session)
	}

	if (len(slots) == 1 && *pinPkcs11 != "") {
		session, err = module.OpenSession(slots[0].id, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
		if err != nil {
			goto no_certs
		}

		err = module.Login(session, pkcs11.CKU_USER, *pinPkcs11)
		if err != nil {
			goto no_certs
		}
		matchingCerts, err = getCerts(module, session, uri, certIdentifier, single)
		if err == nil && len(matchingCerts) > 0 {
			return session, slots[0].id, true, matchingCerts, nil
		}
		module.CloseSession(session)
	}

no_certs:
	err = errors.New("no matching certificates")

	return 0, 0, false, nil, err
}

func GetMatchingPKCSCerts(certIdentifier CertIdentifier, uristr string, lib string) (matchingCerts []*x509.Certificate, err error) {
	var slots []SlotIdInfo
	var module *pkcs11.Ctx
	var session pkcs11.SessionHandle
	var uri *pkcs11uri.Pkcs11URI
	var pin string
	var cert_objs []CertObjInfo

	uri = pkcs11uri.New()
	err = uri.Parse(uristr)
	if err != nil {
		return nil, err
	}

	pin, _ = uri.GetQueryAttribute("pin-value", false)

	module, slots, err = openPKCS11Module(lib)
	if err != nil {
		return nil, err
	}

	session, _, _, cert_objs, err = getMatchingCerts(module, slots, certIdentifier, uri, false, &pin)

	if session != 0 {
		module.CloseSession(session)
	}

	if module != nil {
		module.Finalize()
		module.Destroy()
	}

	for _, obj := range cert_objs {
		matchingCerts = append(matchingCerts, obj.x509)
	}
	return matchingCerts, err
}

// Returns the public key associated with this PKCS11Signer
func (pkcs11Signer *PKCS11Signer) Public() crypto.PublicKey {
	if pkcs11Signer.cert != nil {
		return pkcs11Signer.cert.PublicKey
	}
	return nil
}

// Closes this PKCS11Signer
func (pkcs11Signer *PKCS11Signer) Close() {
	if module := pkcs11Signer.module; module != nil {
		if session := pkcs11Signer.session; session != 0 {
			module.Logout(session)
			module.CloseSession(session)
		}
		module.Finalize()
		module.Destroy()
	}
}

// Implements the crypto.Signer interface and signs the passed in digest
func (pkcs11Signer *PKCS11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	module := pkcs11Signer.module
	session := pkcs11Signer.session
	privateKeyHandle := pkcs11Signer.privateKeyHandle
	keyType := pkcs11Signer.keyType

	var mechanism uint
	if keyType == pkcs11.CKK_EC {
		hash := sha256.Sum256(digest)
		digest = hash[:]
		mechanism = pkcs11.CKM_ECDSA
	} else {
		switch opts.HashFunc() {
		case crypto.SHA256:
			mechanism = pkcs11.CKM_SHA256_RSA_PKCS
		case crypto.SHA384:
			mechanism = pkcs11.CKM_SHA384_RSA_PKCS
		case crypto.SHA512:
			mechanism = pkcs11.CKM_SHA512_RSA_PKCS
		}
	}

	err = module.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}, privateKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("signing initiation failed (%s)", err.Error())
	}

	if pkcs11Signer.pin != "" {
		err = module.Login(session, pkcs11.CKU_CONTEXT_SPECIFIC, pkcs11Signer.pin)
		if err != nil {
			return nil, fmt.Errorf("user re-authentication failed (%s)", err.Error())
		}
	}

	sig, err := module.Sign(session, digest)
	if err != nil {
		return nil, fmt.Errorf("signing failed (%s)", err.Error())
	}

	if mechanism == pkcs11.CKM_ECDSA {
		sig, err = encode_ecdsa_sig_value(sig)
		if err != nil {
			return nil, err
		}

	}
	return sig, nil
}

// Gets the x509.Certificate associated with this PKCS11Signer
func (pkcs11Signer *PKCS11Signer) Certificate() (*x509.Certificate, error) {
	return pkcs11Signer.cert, nil
}

// Checks whether the first certificate issues the second
func certIssues(issuer *x509.Certificate, candidate *x509.Certificate) bool {
	roots := x509.NewCertPool()
	roots.AddCert(issuer)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err := candidate.Verify(opts)
	return err != nil
}

// Gets the certificate chain associated with this PKCS11Signer
func (pkcs11Signer *PKCS11Signer) CertificateChain() (chain []*x509.Certificate, err error) {
	module := pkcs11Signer.module
	session := pkcs11Signer.session
	chain = append(chain, pkcs11Signer.cert)

	var no_identifier CertIdentifier
	certsFound, err := getCerts(module, session, nil, no_identifier, false)
	if err != nil {
		return nil, err
	}

	for true {
		nextInChainFound := false
		for i, curCert := range certsFound {
			curLastCert := chain[len(chain)-1]
			if certIssues(curLastCert, curCert.x509) {
				nextInChainFound = true
				chain = append(chain, curCert.x509)

				// Remove current cert, so that it won't be iterated again
				lastIndex := len(certsFound) - 1
				certsFound[i] = certsFound[lastIndex]
				certsFound = certsFound[:lastIndex]

				break
			}
		}
		if !nextInChainFound {
			break
		}
	}

	return chain, nil
}

// Gets the manufacturer ID for the PKCS #11 module
func getManufacturerId(module *pkcs11.Ctx) (string, error) {
	info, err := module.GetInfo()
	if err != nil {
		return "", err
	}

	return info.ManufacturerID, nil
}

func encode_ecdsa_sig_value(signature []byte) (out []byte, err error) {
	siglen := len(signature) / 2

	return asn1.Marshal(struct {R *big.Int; S *big.Int}{
		big.NewInt(0).SetBytes(signature[:siglen]),
		big.NewInt(0).SetBytes(signature[siglen:])})
}

// Checks whether the private key and certificate are associated with each other
func checkPrivateKeyMatchesCert(module *pkcs11.Ctx, session pkcs11.SessionHandle, keyType uint, alwaysAuth uint, pinPkcs11 string, privateKeyHandle pkcs11.ObjectHandle, certificate *x509.Certificate, manufacturerId string) bool {
	var digestSuffix []byte
	var mechanism uint
	publicKey := certificate.PublicKey
	ecdsaPublicKey, isEcKey := publicKey.(*ecdsa.PublicKey)
	if isEcKey {
		digestSuffixArr := sha256.Sum256(append([]byte("IAM RA"), elliptic.Marshal(ecdsaPublicKey, ecdsaPublicKey.X, ecdsaPublicKey.Y)...))
		digestSuffix = digestSuffixArr[:]
		mechanism = pkcs11.CKM_ECDSA
		if keyType != pkcs11.CKK_EC {
			return false
		}
	}

	rsaPublicKey, isRsaKey := publicKey.(*rsa.PublicKey)
	if isRsaKey {
		digestSuffixArr := sha256.Sum256(append([]byte("IAM RA"), x509.MarshalPKCS1PublicKey(rsaPublicKey)...))
		digestSuffix = digestSuffixArr[:]
		mechanism = pkcs11.CKM_SHA256_RSA_PKCS
		if keyType != pkcs11.CKK_RSA {
			return false
		}
	}
	// "AWS Roles Anywhere Credential Helper PKCS11 Test" || PKCS11_TEST_VERSION ||
	// MANUFACTURER_ID || SHA256("IAM RA" || PUBLIC_KEY_BYTE_ARRAY)
	digest := "AWS Roles Anywhere Credential Helper PKCS11 Test" +
		strconv.Itoa(int(PKCS11_TEST_VERSION)) + manufacturerId + string(digestSuffix)
	digestBytes := []byte(digest)
	hash := sha256.Sum256(digestBytes)
	if isEcKey {
		// For CKM_ECDSA we pass in a hash, not the plain message
		digestBytes = hash[:]
	}

	err := module.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}, privateKeyHandle)
	if err != nil {
		return false
	}

	if alwaysAuth != 0 && pinPkcs11 != "" {
		err = module.Login(session, pkcs11.CKU_CONTEXT_SPECIFIC, pinPkcs11)
		if err != nil {
			return false
		}
	}
	signature, err := module.Sign(session, digestBytes)
	if err != nil {
		return false
	}

	if isEcKey {
		signature, err = encode_ecdsa_sig_value(signature)
		if err != nil {
			return false
		}
		valid := ecdsa.VerifyASN1(ecdsaPublicKey, hash[:], signature)
		return valid
	}

	if isRsaKey {
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signature)
		return err == nil
	}

	return false
}

func bytesToUint(b []byte) (res uint, err error) {
	if len(b) == 1 {
		return uint(b[0]), nil
	}
	if len(b) == 2 {
		var p16 *uint16
		p16 = (*uint16)(unsafe.Pointer(&b[0]))
		return uint(*p16), nil
	}
	if len(b) == 4 {
		var p32 *uint32
		p32 = (*uint32)(unsafe.Pointer(&b[0]))
		return uint(*p32), nil
	}
	if len(b) == 8 {
		var p64 *uint64
		p64 = (*uint64)(unsafe.Pointer(&b[0]))
		return uint(*p64), nil
	}
	return 0, errors.New("Unsupported integer size in bytesToUint")
}


/*
 * Lifted from pkcs11uri.go because it doesn't let us set an attribute
 * from a []byte; only a pct-encoded string.
 * https://github.com/stefanberger/go-pkcs11uri/issues/11
 */

// upper character hex digits needed for pct-encoding
const hexchar = "0123456789ABCDEF"

// escapeAll pct-escapes all characters in the string
func escapeAll(s []byte) string {
        res := make([]byte, len(s)*3)
        j := 0
        for i := 0; i < len(s); i++ {
                c := s[i]
                res[j] = '%'
                res[j+1] = hexchar[c>>4]
                res[j+2] = hexchar[c&0xf]
                j += 3
        }
        return string(res)
}

// Returns a PKCS11Signer, that can be used to sign a payload through a PKCS11-compatible
// cryptographic device
func GetPKCS11Signer(certIdentifier CertIdentifier, libPkcs11 string, certificate *x509.Certificate, certificateChain []*x509.Certificate, privateKeyId string, certificateId string) (signer Signer, signingAlgorithm string, err error) {
	var templatePrivateKey []*pkcs11.Attribute
	var sessionPrivateKeyObjects []pkcs11.ObjectHandle
	var privateKeyHandle pkcs11.ObjectHandle
	var pinPkcs11Bytes []byte
	var module *pkcs11.Ctx
	var session pkcs11.SessionHandle
	var manufacturerId string
	var cert_uri *pkcs11uri.Pkcs11URI
	var key_uri *pkcs11uri.Pkcs11URI
	var logged_in bool
	var slot_nr uint
	var slots []SlotIdInfo
	var pinPkcs11 string
	var cert_obj []CertObjInfo
	var keyAttributes  []*pkcs11.Attribute
	var keyType uint
	var alwaysAuth uint

	module, slots, err = openPKCS11Module(libPkcs11)
	if err != nil {
		goto fail
	}

	if certificate == nil && certificateId != "" {
		cert_uri = pkcs11uri.New()
		err = cert_uri.Parse(certificateId)
	        if (err != nil) {
		    goto fail
		}
		pinPkcs11, _ := cert_uri.GetQueryAttribute("pin-value", false)
		session, slot_nr, logged_in, cert_obj, err = getMatchingCerts(module, slots, certIdentifier, cert_uri, true, &pinPkcs11)
		if err != nil {
			goto fail
		}
		certificate = cert_obj[0].x509
	}

	if (privateKeyId != "") {
		key_uri = pkcs11uri.New()
		err = key_uri.Parse(privateKeyId)
		if (err != nil) {
			goto fail
		}
	} else {
		key_uri = cert_uri;
	}
	pinPkcs11, _ = key_uri.GetQueryAttribute("pin-value", false)

	slots = matchSlots(slots, key_uri)
	if len(slots) == 1 {
		if slot_nr != slots[0].id {
			if session != 0 {
				module.CloseSession(session)
			}
			session = 0
			logged_in = false
			slot_nr = slots[0].id
		}
	} else {
		for _, slot := range slots {
			if slot.id == slot_nr {
				goto got_slot
			}
		}
		err = errors.New("Could not identify unique slot for PKCS#11 key")
		goto fail
	}

got_slot:
	if session == 0 {
		session, err = module.OpenSession(slot_nr, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
		if err != nil {
			goto fail
		}
	}

	if !logged_in {
		if pinPkcs11 == "" {
			fmt.Fprintln(os.Stderr, "Please enter your user pin:")
			pinPkcs11Bytes, err = term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				err = errors.New("unable to read PKCS#11 user pin")
				goto fail
			}

			pinPkcs11 = string(pinPkcs11Bytes[:])
			strings.Replace(pinPkcs11, "\r", "", -1) // Remove CR
		}

		err = module.Login(session, pkcs11.CKU_USER, pinPkcs11)
		if err != nil {
			goto fail
		}
	}
retry_search:
	templatePrivateKey = getFindTemplate(key_uri, pkcs11.CKO_PRIVATE_KEY)

	if err = module.FindObjectsInit(session, templatePrivateKey); err != nil {
		goto fail
	}
	sessionPrivateKeyObjects, _, err = module.FindObjects(session, MAX_OBJECT_LIMIT)
	if err != nil {
		goto fail
	}
	if err = module.FindObjectsFinal(session); err != nil {
		goto fail
	}

	// Get manufacturer ID once, so that it can be used in the test string to sign when testing candidate private keys
	manufacturerId, err = getManufacturerId(module)
	if err != nil {
		goto fail
	}

	for _, curPrivateKeyHandle := range sessionPrivateKeyObjects {
		// Find the signing algorithm
		keyAttributes = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
		}
		if keyAttributes, err = module.GetAttributeValue(session, curPrivateKeyHandle, keyAttributes); err != nil {
			continue
		}
		keyType, err = bytesToUint(keyAttributes[0].Value)
		if err != nil {
			goto fail
		}

		keyAttributes[0] = pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, 0)
		keyAttributes, err = module.GetAttributeValue(session, curPrivateKeyHandle, keyAttributes)
		if err == nil {
			alwaysAuth, err = bytesToUint(keyAttributes[0].Value)
			if err != nil {
				goto fail
			}
		} else {
			alwaysAuth = 0
		}


		if certificate == nil ||
			checkPrivateKeyMatchesCert(module, session, keyType, alwaysAuth, pinPkcs11, curPrivateKeyHandle, certificate, manufacturerId) {
			privateKeyHandle = curPrivateKeyHandle
			break
		}
	}

	if privateKeyHandle == 0 {
		/*
		 * "If the key is not found and the original search was by
		 * CKA_LABEL of the certificate, then repeat the search using
		 * the CKA_ID of the certificate that was actually found, but
		 * not requiring a CKA_LABEL match."
		 *
		 * http://david.woodhou.se/draft-woodhouse-cert-best-practice.html#rfc.section.8.2
		 */
		if (privateKeyId == "" || privateKeyId == certificateId) &&
			certificate != nil && cert_obj[0].id != nil {
			_, key_had_label := key_uri.GetPathAttribute("object", false)
			if key_had_label {
				key_uri.RemovePathAttribute("object")
				key_uri.SetPathAttribute("id", escapeAll(cert_obj[0].id))
				goto retry_search
			}
		}

		err = errors.New("unable to find matching private key")
		goto fail
	}

	switch (keyType) {
	case pkcs11.CKK_EC:
		signingAlgorithm = aws4_x509_ecdsa_sha256
	case pkcs11.CKK_RSA:
		signingAlgorithm = aws4_x509_rsa_sha256
	default:
		return nil, "", errors.New("unsupported algorithm")
	}

	if alwaysAuth == 0 {
		pinPkcs11 = ""
	}

	return &PKCS11Signer{certificate, nil, module, session, privateKeyHandle, pinPkcs11, keyType}, signingAlgorithm, nil

fail:
	if module != nil {
		if session != 0 {
			module.Logout(session)
			module.CloseSession(session)
		}
		module.Finalize()
		module.Destroy()
	}

	return nil, "", err
}
