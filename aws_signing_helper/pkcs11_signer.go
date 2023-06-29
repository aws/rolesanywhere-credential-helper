package aws_signing_helper

// RFC7512 defines a standard URI format for referencing PKCS#11 objects.
//
// Decent applications should silently accept these in place of a file name,
// and Do The Right Thing. There should be no additional configuration or
// anything else to confuse the user.
//
// Users shouldn't even need to specify the PKCS#11 "provider" librrary, as
// most systems should use p11-kit for that. Properly packaged providers
// will ship with a p11-kit 'module' file which makes them discoverable.
//
// p11-kit has system-wide and per-user configuration for providers, and
// automatically makes all the discovered tokens available through the
// "p11-kit-proxy.so" provider module. We just use *that* by default.
//
// So all the user should ever have to do is something like
//     --private-key pkcs11:manufacturer=piv_II;id=%01
// or --certificate pkcs11:object=Certificate%20for%20Digital%20Signature?pin-value=123456
//
// The PKCS#11 URI is a bit of a misnomer; it's not really a unique
// identifier — it's more of a search term; specifying the constraints
// which must match either the token or the object therein. Some rules
// for how you apply those search constraints, and in particular where
// you look for a matching private key after finding a certificate, are
// at http://david.woodhou.se/draft-woodhouse-cert-best-practice.html#rfc.section.8.2
//
// This code is based on the C implementation at
// https://gitlab.com/openconnect/openconnect/-/blob/v9.12/openssl-pkcs11.c
//
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/miekg/pkcs11"
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
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
	keyType          uint
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

// Used to enumerate slots with all token/slot info for matching
type SlotIdInfo struct {
	id      uint
	info    pkcs11.SlotInfo
	tokInfo pkcs11.TokenInfo
}

// Return true if the URI specifies the attribute and it *doesn't* match
func mismatchAttr(uri *pkcs11uri.Pkcs11URI, attr string, val string) bool {
	uriVal, ok := uri.GetPathAttribute(attr, false)
	return ok && uriVal != val
}

// Return the set of slots which match the given uri
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
		if mismatchAttr(uri, "token", slot.tokInfo.Label) ||
			mismatchAttr(uri, "model", slot.tokInfo.Model) ||
			mismatchAttr(uri, "manufacturer", slot.tokInfo.ManufacturerID) ||
			mismatchAttr(uri, "serial", slot.tokInfo.SerialNumber) ||
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
	var slotIds []uint

	// In a properly configured system, nobody should need to override this.
	if lib == "" {
		switch runtime.GOOS {
		case "darwin":
			lib = "p11-kit-proxy.dylib"
		case "windows":
			lib = "p11-kit-proxy.dll"
		default:
			lib = "p11-kit-proxy.so"
		}
	}

	module = pkcs11.New(lib)
	if module == nil {
		err = errors.New("Failed to load provider library " + lib)
		goto fail
	}
	if err = module.Initialize(); err != nil {
		goto fail
	}

	slotIds, err = module.GetSlotList(true)
	if err != nil {
		goto fail
	}

	for _, slotId := range slotIds {
		var slotIdInfo SlotIdInfo
		var slotErr error

		slotIdInfo.id = slotId
		slotIdInfo.info, slotErr = module.GetSlotInfo(slotId)
		if slotErr != nil {
			continue
		}
		slotIdInfo.tokInfo, slotErr = module.GetTokenInfo(slotId)
		if slotErr != nil {
			continue
		}

		slots = append(slots, slotIdInfo)
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

// Convert the object-related fields in a URI to pkcs11.Attributes for FindObjectsInit()
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

// In our list of certs we want to remember the CKA_ID/CKA_LABEL too
type CertObjInfo struct {
	id    []byte
	label []byte
	x509  *x509.Certificate
}

// Gets certificate(s) within the PKCS#11 session (i.e. a given token) that
// match the given URI
func getCertsInSession(module *pkcs11.Ctx, session pkcs11.SessionHandle, uri *pkcs11uri.Pkcs11URI) (certs []CertObjInfo, err error) {
	var sessionCertObjects []pkcs11.ObjectHandle
	var certObjects []pkcs11.ObjectHandle
	var templateCrt []*pkcs11.Attribute

	// Convert the URI into a template for FindObjectsInit()
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
		if len(sessionCertObjects) < MAX_OBJECT_LIMIT {
			break
		}
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

		var certObj CertObjInfo

		certObj.x509, err = x509.ParseCertificate(rawCert) // nosemgrep
		if err != nil {
			return nil, errors.New("error parsing certificate")
		}

		// Fetch the CKA_ID and CKA_LABEL of the matching cert(s), so
		// that they can be used later when hunting for the matching
		// key.
		crtAttributes[0] = pkcs11.NewAttribute(pkcs11.CKA_ID, 0)
		crtAttributes, err = module.GetAttributeValue(session, certObject, crtAttributes)
		if err == nil {
			certObj.id = crtAttributes[0].Value
		}

		crtAttributes[0] = pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0)
		crtAttributes, err = module.GetAttributeValue(session, certObject, crtAttributes)
		if err == nil {
			certObj.label = crtAttributes[0].Value
		}

		certs = append(certs, certObj)
	}

	return certs, nil
}

// Scan all matching slots to until we find certificates that match the URI.
//
// NB: It's generally only looking for *one* cert to use. If you want
// `p11tool --list-certificates`, use that instead.
func getMatchingCerts(module *pkcs11.Ctx, slots []SlotIdInfo, uri *pkcs11uri.Pkcs11URI, pinPkcs11 *string, single bool) (slotNr uint, matchingCerts []CertObjInfo, err error) {
	var session pkcs11.SessionHandle

	if uri != nil {
		slots = matchSlots(slots, uri)
	}

	// http://david.woodhou.se/draft-woodhouse-cert-best-practice.html#rfc.section.8.1
	//
	// "For locating certificates, applications first iterate over the
	// available tokens without logging in to them. In each token which
	// matches the provided PKCS#11 URI, a search is performed for
	// matching certificate objects."
	for _, slot := range slots {
		session, err = module.OpenSession(slot.id, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
		if err != nil {
			module.CloseSession(session)
			continue
		}

		curMatchingCerts, err := getCertsInSession(module, session, uri)
		if err == nil && len(curMatchingCerts) > 0 {
			matchingCerts = append(matchingCerts, curMatchingCerts...)
			// We only care about this value when there is a single matching
			// certificate found.
			slotNr = slot.id
		}
		module.CloseSession(session)
	}

	if single && len(matchingCerts) > 1 {
		err = errors.New("multiple matching certificates")
		goto fail
	}

	if len(matchingCerts) > 1 {
		return slotNr, matchingCerts, nil
	}

	// If there is exactly one matching certificate found without logging in
	// to any of the tokens, then return that one.
	if single && len(matchingCerts) == 1 {
		return slotNr, matchingCerts, nil
	}

	// http://david.woodhou.se/draft-woodhouse-cert-best-practice.html#rfc.section.8.1
	//
	// "If no match is found, and precisely one token was matched by the
	// specified URI, then the application attempts to log in to that
	// token using a PIN [...]. Another search is performed for matching
	// objects, which this time will return even any certificate objects
	// with the CKA_PRIVATE attribute. Is it important to note that the
	// login should only be attempted if there is precisely one token
	// which matches the URI, and not if there are multiple possible
	// tokens in which the object could reside."
	if len(slots) == 1 && *pinPkcs11 != "" {
		errNoMatchingCerts := errors.New("no matching certificates")

		session, err = module.OpenSession(slots[0].id, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
		if err != nil {
			err = errNoMatchingCerts
			goto fail
		}

		err = module.Login(session, pkcs11.CKU_USER, *pinPkcs11)
		if err != nil {
			err = errNoMatchingCerts
			goto fail
		}

		curMatchingCerts, err := getCertsInSession(module, session, uri)
		if err == nil && len(curMatchingCerts) > 0 {
			matchingCerts = append(matchingCerts, curMatchingCerts...)
			// We only care about this value when there is a single matching
			// certificate found.
			slotNr = slots[0].id
		}
		module.Logout(session)
		module.CloseSession(session)
	}

	if single && len(matchingCerts) > 0 {
		err = errors.New("multiple matching certificates")
		goto fail
	}
	if len(matchingCerts) == 0 {
		err = errors.New("no matching certificates")
		goto fail
	}

	// Exactly one matching certificate after logging into the appropriate token
	// iff single is true (otherwise there can be multiple matching certificates)
	return slotNr, matchingCerts, nil

fail:
	if session != 0 {
		module.Logout(session)
		module.CloseSession(session)
	}
	return 0, nil, err
}

// Used to implement a cut-down version of `p11tool --list-certificates`.
func GetMatchingPKCSCerts(uriStr string, lib string) (matchingCerts []*x509.Certificate, err error) {
	var slots []SlotIdInfo
	var module *pkcs11.Ctx
	var uri *pkcs11uri.Pkcs11URI
	var pin string
	var certObjs []CertObjInfo

	uri = pkcs11uri.New()
	err = uri.Parse(uriStr)
	if err != nil {
		return nil, err
	}

	pin, _ = uri.GetQueryAttribute("pin-value", false)

	module, slots, err = openPKCS11Module(lib)
	if err != nil {
		return nil, err
	}

	_, certObjs, err = getMatchingCerts(module, slots, uri, &pin, false)

	if module != nil {
		module.Finalize()
		module.Destroy()
	}

	for _, obj := range certObjs {
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

	// XXX: If you use this outside the context of IAM RA, be aware that
	// you'll want to use something other than SHA256 in many cases.
	// For TLSv1.3 the hash needs to precisely match the bit size of the
	// curve, IIRC. And you'll need RSA-PSS too. You might find that
	// ThalesIgnite/crypto11 has some of that.
	// e.g. https://github.com/ThalesIgnite/crypto11/blob/master/rsa.go#L230
	var mechanism uint
	if keyType == pkcs11.CKK_EC {
		switch opts.HashFunc() {
		case crypto.SHA256:
			hash := sha256.Sum256(digest)
			digest = hash[:]
		case crypto.SHA384:
			hash := sha512.Sum384(digest)
			digest = hash[:]
		case crypto.SHA512:
			hash := sha512.Sum512(digest)
			digest = hash[:]
		}
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

	// We assume it's the same PIN as the token itself? Which was only
	// "saved" for us in pkcs11Signer if the CKA_ALWAYS_AUTHENTICATE
	// attribute was set.
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

	// Yay, we have to do the ASN.1 encoding of the R, S values ourselves.
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

	certsFound, err := getCertsInSession(module, session, nil)
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

// Because of *course* we have to do this for ourselves.
//
// Create the DER-encoded SEQUENCE containing R and S:
//
//	Ecdsa-Sig-Value ::= SEQUENCE {
//	  r                   INTEGER,
//	  s                   INTEGER
//	}
//
// This is defined in RFC3279 §2.2.3 as well as SEC.1.
// I can't find anything which mandates DER but I've seen
// OpenSSL refusing to verify it with indeterminate length.
func encode_ecdsa_sig_value(signature []byte) (out []byte, err error) {
	siglen := len(signature) / 2

	return asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{
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

	// XX: Why are we duplicating this code from our actual Sign() function?
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

// This is not my proudest moment. But there's no binary.NativeEndian.
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

// Given an optional certificate either as *x509.Certificate (because it was
// already found in a file) or as a PKCS#11 URI, and an optional private key
// PKCS#11 URI, return a PKCS11Signer that can be used to sign a payload
// through a PKCS#11-compatible cryptographic device
func GetPKCS11Signer(libPkcs11 string, certificate *x509.Certificate, certificateChain []*x509.Certificate, privateKeyId string, certificateId string) (signer Signer, signingAlgorithm string, err error) {
	var templatePrivateKey []*pkcs11.Attribute
	var sessionPrivateKeyObjects []pkcs11.ObjectHandle
	var privateKeyHandle pkcs11.ObjectHandle
	var module *pkcs11.Ctx
	var session pkcs11.SessionHandle
	var manufacturerId string
	var certUri *pkcs11uri.Pkcs11URI
	var keyUri *pkcs11uri.Pkcs11URI
	var slotNr uint
	var slots []SlotIdInfo
	var pinPkcs11 string
	var certObj []CertObjInfo
	var keyAttributes []*pkcs11.Attribute
	var keyType uint
	var alwaysAuth uint
	var privateKeyObjects []pkcs11.ObjectHandle

	module, slots, err = openPKCS11Module(libPkcs11)
	if err != nil {
		goto fail
	}

	// If a PKCS#11 URI was provided for the certificate, find it.
	if certificate == nil && certificateId != "" {
		certUri = pkcs11uri.New()
		err = certUri.Parse(certificateId)
		if err != nil {
			goto fail
		}
		pinPkcs11, _ := certUri.GetQueryAttribute("pin-value", false)
		slotNr, certObj, err = getMatchingCerts(module, slots, certUri, &pinPkcs11, true)
		if err != nil {
			goto fail
		}
		certificate = certObj[0].x509
	}

	// If no explicit private-key option was given, use it. Otherwise
	// we look in the same place as the certificate URI as directed by
	// http://david.woodhou.se/draft-woodhouse-cert-best-practice.html#rfc.section.8.2
	if privateKeyId != "" {
		keyUri = pkcs11uri.New()
		err = keyUri.Parse(privateKeyId)
		if err != nil {
			goto fail
		}
	} else {
		keyUri = certUri
	}
	pinPkcs11, _ = keyUri.GetQueryAttribute("pin-value", false)

	// This time we're looking for a *single* slot, as we (presumably)
	// will have to log in to access the key.
	slots = matchSlots(slots, keyUri)
	if len(slots) == 1 {
		if slotNr != slots[0].id {
			slotNr = slots[0].id
		}
	} else {
		// If the URI matched multiple slots *but* one of them is the
		// one (slotNr) that the certificate was found in, then use
		// that.
		for _, slot := range slots {
			if slot.id == slotNr {
				goto got_slot
			}
		}
		err = errors.New("Could not identify unique slot for PKCS#11 key")
		goto fail
	}

got_slot:
	session, err = module.OpenSession(slotNr, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
	if err != nil {
		goto fail
	}

	// And *now* we fall back to prompting the user for a PIN if necessary.
	if pinPkcs11 == "" {
		parseErrMsg := "unable to read PKCS#11 user pin"
		prompt := "Please enter your user pin:"
		for true {
			pinPkcs11, err = GetPassword(prompt, parseErrMsg)
			if err != nil && err.Error() == parseErrMsg {
				continue
			}

			err = module.Login(session, pkcs11.CKU_USER, pinPkcs11)
			if err != nil {
				// Loop on failure in case the user mistyped.
				if strings.Contains(err.Error(), "CKR_PIN_INCORRECT") {
					prompt = "Incorrect user pin. Please re-enter your user pin:"
					continue
				}
				goto fail
			}
			break
		}
	} else {
		err = module.Login(session, pkcs11.CKU_USER, pinPkcs11)
		if err != nil {
			goto fail
		}
	}

retry_search:
	templatePrivateKey = getFindTemplate(keyUri, pkcs11.CKO_PRIVATE_KEY)

	if err = module.FindObjectsInit(session, templatePrivateKey); err != nil {
		goto fail
	}
	for true {
		sessionPrivateKeyObjects, _, err = module.FindObjects(session, MAX_OBJECT_LIMIT)
		if err != nil {
			goto fail
		}
		if len(sessionPrivateKeyObjects) == 0 {
			break
		}
		privateKeyObjects = append(privateKeyObjects, sessionPrivateKeyObjects...)
		if len(sessionPrivateKeyObjects) < MAX_OBJECT_LIMIT {
			break
		}
	}
	if err = module.FindObjectsFinal(session); err != nil {
		goto fail
	}

	// Get manufacturer ID once, so that it can be used in the test string to sign when testing candidate private keys
	manufacturerId, err = getManufacturerId(module)
	if err != nil {
		goto fail
	}

	// If we found multiple keys, try them until we find the one
	// that actually matches the cert. More realistically, there
	// will be only one. Sanity check that it matches the cert.
	for _, curPrivateKeyHandle := range privateKeyObjects {
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
		/* "If the key is not found and the original search was by
		 * CKA_LABEL of the certificate, then repeat the search using
		 * the CKA_ID of the certificate that was actually found, but
		 * not requiring a CKA_LABEL match."
		 *
		 * http://david.woodhou.se/draft-woodhouse-cert-best-practice.html#rfc.section.8.2
		 */
		if (privateKeyId == "" || privateKeyId == certificateId) &&
			certificate != nil && certObj[0].id != nil {
			_, key_had_label := keyUri.GetPathAttribute("object", false)
			if key_had_label {
				keyUri.RemovePathAttribute("object")
				keyUri.SetPathAttribute("id", escapeAll(certObj[0].id))
				goto retry_search
			}
		}

		err = errors.New("unable to find matching private key")
		goto fail
	}

	switch keyType {
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

// Prompts the user for their password
func GetPassword(prompt string, parseErrMsg string) (string, error) {
	fmt.Fprintln(os.Stderr, prompt)
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", errors.New(parseErrMsg)
	}

	password := string(passwordBytes[:])
	strings.Replace(password, "\r", "", -1) // Remove CR
	return password, nil
}
