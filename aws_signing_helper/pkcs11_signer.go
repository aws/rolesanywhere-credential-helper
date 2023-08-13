package aws_signing_helper

// RFC7512 defines a standard URI format for referencing PKCS#11 objects.
//
// Decent applications should silently accept these in place of a file name,
// and Do The Right Thing. There should be no additional configuration or
// anything else to confuse the user.
//
// Users shouldn't even need to specify the PKCS#11 "provider" library, as
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
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/miekg/pkcs11"
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
	"golang.org/x/term"
)

var PKCS11_TEST_VERSION int16 = 1
var MAX_OBJECT_LIMIT int = 1000

// In our list of certs, we want to remember the CKA_ID/CKA_LABEL too.
type CertObjInfo struct {
	id    []byte
	label []byte
	cert  *x509.Certificate
}

// Used to enumerate slots with all token/slot info for matching.
type SlotIdInfo struct {
	id      uint
	info    pkcs11.SlotInfo
	tokInfo pkcs11.TokenInfo
}

type PKCS11Signer struct {
	certObj            CertObjInfo
	certChain          []*x509.Certificate
	module             *pkcs11.Ctx
	userPin            string
	alwaysAuth         uint
	contextSpecificPin string
	certUri            *pkcs11uri.Pkcs11URI
	keyUri             *pkcs11uri.Pkcs11URI
	session            pkcs11.SessionHandle
	keyType            uint
	privateKeyHandle   pkcs11.ObjectHandle
	loggedIn           bool
	certSlotNr         uint
	slots              []SlotIdInfo
}

// Initialize a PKCS#11 module.
func initializePKCS11Module(lib string) (module *pkcs11.Ctx, err error) {
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

	return module, nil

fail:
	if module != nil {
		module.Finalize()
		module.Destroy()
	}
	return nil, err
}

// Enumerate slots in the PKCS#11 module. This method assumes that the
// module isn't nil and has been initialized.
func enumerateSlotsInPKCS11Module(module *pkcs11.Ctx) (slots []SlotIdInfo, err error) {
	var slotIds []uint

	slotIds, err = module.GetSlotList(true)
	if err != nil {
		return nil, err
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

	return slots, nil
}

// Return true if the URI specifies the attribute and it *doesn't* match
func mismatchAttr(uri *pkcs11uri.Pkcs11URI, attr string, val string) bool {
	var (
		uriVal string
		ok     bool
	)

	uriVal, ok = uri.GetPathAttribute(attr, false)
	return ok && uriVal != val
}

// Return the set of slots which match the given uri
func matchSlots(slots []SlotIdInfo, uri *pkcs11uri.Pkcs11URI) (matches []SlotIdInfo) {
	var (
		uriSlotNr uint64
		uriSlot   string
		ok        bool
	)

	if uri == nil {
		return slots
	}

	uriSlot, ok = uri.GetPathAttribute("slot-id", false)
	if ok {
		uriSlotNr, _ = strconv.ParseUint(uriSlot, 0, 32)
	}

	for _, slot := range slots {
		if uriSlotNr != 0 && uriSlotNr != uint64(slot.id) {
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

// Convert the object-related fields in a URI to []*pkcs11.Attribute for FindObjectsInit()
func getFindTemplate(uri *pkcs11uri.Pkcs11URI, class uint) (template []*pkcs11.Attribute) {
	var (
		v  string
		ok bool
	)

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

// Gets certificate(s) within the PKCS#11 session (i.e. a given token) that
// matches the given URI.
func getCertsInSession(module *pkcs11.Ctx, slotId uint, session pkcs11.SessionHandle, uri *pkcs11uri.Pkcs11URI) (certs []CertObjInfo, err error) {
	var (
		sessionCertObjects []pkcs11.ObjectHandle
		certObjects        []pkcs11.ObjectHandle
		templateCrt        []*pkcs11.Attribute
	)

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

		certObj.cert, err = x509.ParseCertificate(rawCert) // nosemgrep
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
// If there is at least one matching certificate found, the returned session
// will be left open and returned. The session may also be logged into in the
// case that the certificate being searched for could only be found after
// logging in to the token.
//
// NB: It's generally only looking for *one* cert to use. If you want
// `p11tool --list-certificates`, use that instead.
func getMatchingCerts(module *pkcs11.Ctx, slots []SlotIdInfo, uri *pkcs11uri.Pkcs11URI, userPin string, single bool) (matchedSlot SlotIdInfo, session pkcs11.SessionHandle, loggedIn bool, matchingCerts []CertObjInfo, err error) {
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
		curSession, err := module.OpenSession(slot.id, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
		if err != nil {
			module.CloseSession(curSession)
			continue
		}

		curMatchingCerts, err := getCertsInSession(module, slot.id, curSession, uri)
		if err == nil && len(curMatchingCerts) > 0 {
			matchingCerts = append(matchingCerts, curMatchingCerts...)
			// We only care about this value when there is a single matching
			// certificate found.
			if matchedSlot == (SlotIdInfo{}) {
				matchedSlot = slot
				session = curSession
				goto skip
			}
		}
		module.CloseSession(curSession)
	skip:
	}

	if len(matchingCerts) >= 1 {
		goto foundCert
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
	if len(slots) == 1 && userPin != "" {
		errNoMatchingCerts := errors.New("no matching certificates")

		curSession, err := module.OpenSession(slots[0].id, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
		if err != nil {
			err = errNoMatchingCerts
			goto fail
		}

		err = module.Login(curSession, pkcs11.CKU_USER, userPin)
		if err != nil {
			err = errNoMatchingCerts
			goto fail
		}

		curMatchingCerts, err := getCertsInSession(module, slots[0].id, curSession, uri)
		if err == nil && len(curMatchingCerts) > 0 {
			matchingCerts = append(matchingCerts, curMatchingCerts...)
			// We only care about this value when there is a single matching
			// certificate found.
			if session == 0 {
				loggedIn = true
				matchedSlot = slots[0]
				session = curSession
				goto foundCert
			}
		}
		module.Logout(curSession)
		module.CloseSession(curSession)
	}

	// No matching certificates
	err = errors.New("no matching certificates")
	goto fail

foundCert:
	if single && len(matchingCerts) > 1 {
		err = errors.New("multiple matching certificates")
		goto fail
	}

	// Exactly one matching certificate after logging into the appropriate token
	// iff single is true (otherwise there can be multiple matching certificates).
	return matchedSlot, session, loggedIn, matchingCerts, nil

fail:
	if session != 0 {
		module.Logout(session)
		module.CloseSession(session)
	}
	return SlotIdInfo{}, session, false, nil, err
}

// Used to implement a cut-down version of `p11tool --list-certificates`.
func GetMatchingPKCSCerts(uriStr string, lib string) (matchingCerts []CertificateContainer, err error) {
	var (
		slots    []SlotIdInfo
		module   *pkcs11.Ctx
		uri      *pkcs11uri.Pkcs11URI
		userPin  string
		certObjs []CertObjInfo
		session  pkcs11.SessionHandle
		loggedIn bool
		slot     SlotIdInfo
	)

	uri = pkcs11uri.New()
	err = uri.Parse(uriStr)
	if err != nil {
		return nil, err
	}

	userPin, _ = uri.GetQueryAttribute("pin-value", false)

	module, err = initializePKCS11Module(lib)
	if err != nil {
		goto cleanUp
	}

	slots, err = enumerateSlotsInPKCS11Module(module)
	if err != nil {
		goto cleanUp
	}

	slot, session, loggedIn, certObjs, err = getMatchingCerts(module, slots, uri, userPin, false)
	if err != nil {
		goto cleanUp
	}

	for _, obj := range certObjs {
		curUri := pkcs11uri.New()
		curUri.AddPathAttribute("model", slot.tokInfo.Model)
		curUri.AddPathAttribute("manufacturer", slot.tokInfo.ManufacturerID)
		curUri.AddPathAttribute("serial", slot.tokInfo.SerialNumber)
		curUri.AddPathAttribute("slot-description", slot.info.SlotDescription)
		curUri.AddPathAttribute("slot-manufacturer", slot.info.ManufacturerID)
		if obj.id != nil {
			curUri.AddPathAttribute("id", string(obj.id[:]))
		}
		if obj.label != nil {
			curUri.AddPathAttribute("object", string(obj.label[:]))
		}
		curUri.AddPathAttribute("type", "cert")
		curUriStr, err := curUri.Format() // nosemgrep
		if err != nil {
			curUriStr = ""
		}
		matchingCerts = append(matchingCerts, CertificateContainer{obj.cert, curUriStr})
	}

	// Note that this clean up should happen regardless of failure.
cleanUp:
	if module != nil {
		if session != 0 {
			if loggedIn {
				module.Logout(session)
			}
			module.CloseSession(session)
		}
		module.Finalize()
		module.Destroy()
	}

	return matchingCerts, err
}

// Returns the public key associated with this PKCS11Signer.
func (pkcs11Signer *PKCS11Signer) Public() crypto.PublicKey {
	var (
		cert    *x509.Certificate
		err     error
		certUri *pkcs11uri.Pkcs11URI
	)

	certUri = pkcs11Signer.certUri
	if certUri == nil {
		return nil
	}

	cert, err = pkcs11Signer.Certificate()
	if err == nil {
		return cert.PublicKey
	}

	return nil
}

// Closes this PKCS11Signer.
func (pkcs11Signer *PKCS11Signer) Close() {
	var (
		module   *pkcs11.Ctx
		session  pkcs11.SessionHandle
		loggedIn bool
	)

	module = pkcs11Signer.module
	session = pkcs11Signer.session
	loggedIn = pkcs11Signer.loggedIn

	if module != nil {
		if session != 0 {
			if loggedIn {
				module.Logout(session)
			}
			module.CloseSession(session)
		}
		module.Finalize()
		module.Destroy()
	}

	pkcs11Signer.session = 0
	pkcs11Signer.certSlotNr = 0
	pkcs11Signer.privateKeyHandle = 0
	pkcs11Signer.alwaysAuth = 0
	pkcs11Signer.loggedIn = false
	pkcs11Signer.slots = nil
	pkcs11Signer.module = nil
}

// Sometimes, it may be preferable to leave sessions open since there are
// multiple functions that the PKCS11Signer has to perform that require
// sessions to be left open. After each of those functions are run,
// CloseSession can be called.
func (pkcs11Signer *PKCS11Signer) CloseSession() {
	var (
		module   *pkcs11.Ctx
		session  pkcs11.SessionHandle
		loggedIn bool
	)

	module = pkcs11Signer.module
	session = pkcs11Signer.session

	if module != nil {
		if session != 0 {
			if loggedIn {
				module.Logout(session)
			}
			module.CloseSession(session)
		}
	}

	pkcs11Signer.session = 0
	pkcs11Signer.certSlotNr = 0
	pkcs11Signer.privateKeyHandle = 0
	pkcs11Signer.alwaysAuth = 0
	pkcs11Signer.loggedIn = false
	pkcs11Signer.slots = nil
}

// Helper function to sign a digest using a PKCS#11 private key handle.
func signHelper(module *pkcs11.Ctx, session pkcs11.SessionHandle, privateKeyHandle pkcs11.ObjectHandle, alwaysAuth uint, pkcs11Pin string, keyType uint, digest []byte, hashFunc crypto.Hash) (contextSpecificPin string, signature []byte, err error) {
	// XXX: If you use this outside the context of IAM RA, be aware that
	// you'll want to use something other than SHA256 in many cases.
	// For TLSv1.3 the hash needs to precisely match the bit size of the
	// curve, IIRC. And you'll need RSA-PSS too. You might find that
	// ThalesIgnite/crypto11 has some of that.
	// e.g. https://github.com/ThalesIgnite/crypto11/blob/master/rsa.go#L230
	var mechanism uint
	if keyType == pkcs11.CKK_EC {
		switch hashFunc {
		case crypto.SHA256:
			hash := sha256.Sum256(digest)
			digest = hash[:]
		case crypto.SHA384:
			hash := sha512.Sum384(digest)
			digest = hash[:]
		case crypto.SHA512:
			hash := sha512.Sum512(digest)
			digest = hash[:]
		default:
			return "", nil, ErrUnsupportedHash
		}
		mechanism = pkcs11.CKM_ECDSA
	} else {
		switch hashFunc {
		case crypto.SHA256:
			mechanism = pkcs11.CKM_SHA256_RSA_PKCS
		case crypto.SHA384:
			mechanism = pkcs11.CKM_SHA384_RSA_PKCS
		case crypto.SHA512:
			mechanism = pkcs11.CKM_SHA512_RSA_PKCS
		default:
			return "", nil, ErrUnsupportedHash
		}
	}

	err = module.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}, privateKeyHandle)
	if err != nil {
		return "", nil, fmt.Errorf("signing initiation failed (%s)", err.Error())
	}

	if alwaysAuth != 0 {
		if pkcs11Pin != "" {
			err = module.Login(session, pkcs11.CKU_CONTEXT_SPECIFIC, pkcs11Pin)
			if err == nil {
				goto afterContextSpecificLogin
			} else {
				if Debug {
					fmt.Fprintf(os.Stderr, "user re-authentication attempt failed (%s)", err.Error())
				}
			}
		}
		passwordName := "context-specific pin"
		finalAuthErrMsg := "user re-authentication failed (%s)"
		_, err = pkcs11PasswordPrompt(module, session, pkcs11.CKU_CONTEXT_SPECIFIC, passwordName, finalAuthErrMsg)
		if err != nil {
			return "", nil, err
		}
	}

afterContextSpecificLogin:
	sig, err := module.Sign(session, digest)
	if err != nil {
		return pkcs11Pin, nil, fmt.Errorf("signing failed (%s)", err.Error())
	}

	// Yay, we have to do the ASN.1 encoding of the R, S values ourselves.
	if mechanism == pkcs11.CKM_ECDSA {
		sig, err = encodeEcdsaSigValue(sig)
		if err != nil {
			return pkcs11Pin, nil, err
		}
	}

	return pkcs11Pin, sig, nil
}

func getPKCS11Key(module *pkcs11.Ctx, session pkcs11.SessionHandle, loggedIn bool, certUri *pkcs11uri.Pkcs11URI, keyUri *pkcs11uri.Pkcs11URI, certSlotNr uint, certObj CertObjInfo, userPin string, contextSpecificPin string, slots []SlotIdInfo) (_session pkcs11.SessionHandle, keyType uint, privateKeyHandle pkcs11.ObjectHandle, alwaysAuth uint, _contextSpecificPin string, err error) {
	var (
		keySlotNr          uint
		manufacturerId     string
		templatePrivateKey []*pkcs11.Attribute
		privateKeyObjects  []pkcs11.ObjectHandle
		keyAttributes      []*pkcs11.Attribute
	)

	if keyUri == nil {
		keyUri = certUri
	}
	userPin, _ = keyUri.GetQueryAttribute("pin-value", false)

	// This time we're looking for a *single* slot, as we (presumably)
	// will have to log in to access the key.
	slots = matchSlots(slots, keyUri)
	if len(slots) == 1 {
		if certSlotNr != slots[0].id {
			keySlotNr = slots[0].id
			manufacturerId = slots[0].info.ManufacturerID
			if session != 0 {
				if loggedIn {
					module.Logout(session)
					module.CloseSession(session)
				}
			}
			loggedIn = false
			session = 0
		}
	} else {
		// If the URI matched multiple slots *but* one of them is the
		// one (certSlot.id) that the certificate was found in, then use
		// that.
		for _, slot := range slots {
			if certSlotNr == slot.id {
				keySlotNr = slot.id
				manufacturerId = slot.info.ManufacturerID
				goto got_slot
			}
		}
		err = errors.New("Could not identify unique slot for PKCS#11 key")
		goto fail
	}

got_slot:
	if session == 0 {
		session, err = module.OpenSession(keySlotNr, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
	}
	if err != nil {
		goto fail
	}

	// And *now* we fall back to prompting the user for a PIN if necessary.
	if !loggedIn {
		if userPin == "" {
			passwordName := "user pin"
			finalAuthErrMsg := "user authentication failed (%s)"
			_, err = pkcs11PasswordPrompt(module, session, pkcs11.CKU_USER, passwordName, finalAuthErrMsg)
			if err != nil {
				goto fail
			}
		} else {
			err = module.Login(session, pkcs11.CKU_USER, userPin)
			if err != nil {
				goto fail
			}
		}
	}

retry_search:
	templatePrivateKey = getFindTemplate(keyUri, pkcs11.CKO_PRIVATE_KEY)

	if err = module.FindObjectsInit(session, templatePrivateKey); err != nil {
		goto fail
	}
	for true {
		sessionPrivateKeyObjects, _, err := module.FindObjects(session, MAX_OBJECT_LIMIT)
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

		if certObj.cert == nil {
			privateKeyHandle = curPrivateKeyHandle
			break
		}

		curContextSpecificPin := contextSpecificPin
		if curContextSpecificPin == "" {
			curContextSpecificPin = userPin
		}
		privateKeyMatchesCert := false
		curContextSpecificPin, privateKeyMatchesCert = checkPrivateKeyMatchesCert(module, session, keyType, alwaysAuth, curContextSpecificPin, curPrivateKeyHandle, certObj.cert, manufacturerId)
		if privateKeyMatchesCert {
			privateKeyHandle = curPrivateKeyHandle
			contextSpecificPin = curContextSpecificPin
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
		keyUriStr, _ := keyUri.Format()
		certUriStr, _ := certUri.Format()
		if certObj.cert != nil {
			if keyUriStr == certUriStr {
				_, keyHadLabel := keyUri.GetPathAttribute("object", false)
				if keyHadLabel {
					keyUri.RemovePathAttribute("object")
					keyUri.SetPathAttribute("id", escapeAll(certObj.id))
					goto retry_search
				}
			}
		}

		err = errors.New("unable to find matching private key")
		goto fail
	}

	return session, keyType, privateKeyHandle, alwaysAuth, contextSpecificPin, nil

fail:
	return 0, 0, 0, 0, "", err
}

func getCertificate(module *pkcs11.Ctx, certUri *pkcs11uri.Pkcs11URI, userPin string) (certSlot SlotIdInfo, slots []SlotIdInfo, session pkcs11.SessionHandle, loggedIn bool, certObj CertObjInfo, err error) {
	var (
		matchingCerts []CertObjInfo
	)

	slots, err = enumerateSlotsInPKCS11Module(module)
	if err != nil {
		return SlotIdInfo{}, nil, 0, false, CertObjInfo{}, err
	}

	certSlot, session, loggedIn, matchingCerts, err = getMatchingCerts(module, slots, certUri, userPin, true)
	if err != nil {
		return SlotIdInfo{}, nil, 0, false, CertObjInfo{}, err
	}

	return certSlot, slots, session, loggedIn, matchingCerts[0], nil
}

// Implements the crypto.Signer interface and signs the passed in digest
func (pkcs11Signer *PKCS11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var (
		module             *pkcs11.Ctx
		session            pkcs11.SessionHandle
		certUri            *pkcs11uri.Pkcs11URI
		keyUri             *pkcs11uri.Pkcs11URI
		userPin            string
		contextSpecificPin string
		privateKeyHandle   pkcs11.ObjectHandle
		keyType            uint
		certSlotNr         uint
		certObj            CertObjInfo
		slots              []SlotIdInfo
		loggedIn           bool
		alwaysAuth         uint
		certSlot           SlotIdInfo
	)

	hashFunc := opts.HashFunc()

	// The module is the only one that's guaranteed to be initialized properly
	module = pkcs11Signer.module
	userPin = pkcs11Signer.userPin
	contextSpecificPin = pkcs11Signer.contextSpecificPin
	certUri = pkcs11Signer.certUri
	keyUri = pkcs11Signer.keyUri
	privateKeyHandle = pkcs11Signer.privateKeyHandle
	keyType = pkcs11Signer.keyType
	certObj = pkcs11Signer.certObj
	session = pkcs11Signer.session
	loggedIn = pkcs11Signer.loggedIn
	slots = pkcs11Signer.slots
	alwaysAuth = pkcs11Signer.alwaysAuth

	if privateKeyHandle != 0 {
		goto gotPrivateKey
	}

	if certSlotNr != 0 {
		goto gotCert
	}

	if certUri != nil {
		certSlot, slots, session, loggedIn, certObj, err = getCertificate(module, certUri, userPin)
		if err != nil {
			goto fail
		}

		pkcs11Signer.slots = slots
		pkcs11Signer.session = session
		pkcs11Signer.loggedIn = loggedIn
		pkcs11Signer.certSlotNr = certSlot.id
		pkcs11Signer.certObj = certObj
	} else {
		pkcs11Signer.slots, err = enumerateSlotsInPKCS11Module(module)
		if err != nil {
			goto fail
		}
	}
	slots = pkcs11Signer.slots
	certObj = pkcs11Signer.certObj
	loggedIn = pkcs11Signer.loggedIn
	certSlotNr = pkcs11Signer.certSlotNr

gotCert:
	session, keyType, privateKeyHandle, alwaysAuth, contextSpecificPin, err = getPKCS11Key(module, session, loggedIn, certUri, keyUri, certSlotNr, certObj, userPin, contextSpecificPin, slots)
	if err != nil {
		goto fail
	}

	// Save the values we need after finding the key.
	pkcs11Signer.session = session
	pkcs11Signer.keyType = keyType
	pkcs11Signer.privateKeyHandle = privateKeyHandle
	pkcs11Signer.alwaysAuth = alwaysAuth
	pkcs11Signer.contextSpecificPin = contextSpecificPin
	pkcs11Signer.loggedIn = true

gotPrivateKey:
	// We only care about the context-specific PIN when it comes to signing with
	// objects that are marked with CKA_ALWAYS_AUTHENTICATE, which (from my
	// understanding) can be different from the user PIN. If the context-specific
	// PIN has been saved already, use it. Otherwise, default to the user PIN.
	if contextSpecificPin == "" {
		contextSpecificPin = pkcs11Signer.userPin
	}

	_, signature, err = signHelper(module, session, privateKeyHandle, alwaysAuth, contextSpecificPin, keyType, digest, hashFunc)
	if err != nil {
		goto fail
	}

fail:
	return signature, err
}

// Gets the *x509.Certificate associated with this PKCS11Signer
func (pkcs11Signer *PKCS11Signer) Certificate() (certificate *x509.Certificate, err error) {
	var (
		module   *pkcs11.Ctx
		userPin  string
		loggedIn bool
		certSlot SlotIdInfo
		certObj  CertObjInfo
		session  pkcs11.SessionHandle
		certUri  *pkcs11uri.Pkcs11URI
		cert     *x509.Certificate
		slots    []SlotIdInfo
	)

	module = pkcs11Signer.module
	cert = pkcs11Signer.certObj.cert

	if cert != nil {
		return cert, nil
	}

	// Otherwise, get the certificate.
	certSlot, slots, session, loggedIn, certObj, err = getCertificate(module, certUri, userPin)
	if err != nil {
		return nil, err
	}

	pkcs11Signer.slots = slots
	pkcs11Signer.session = session
	pkcs11Signer.loggedIn = loggedIn
	pkcs11Signer.certSlotNr = certSlot.id
	pkcs11Signer.certObj = certObj

	return pkcs11Signer.certObj.cert, nil
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
	var (
		module     *pkcs11.Ctx
		session    pkcs11.SessionHandle
		certChain  []*x509.Certificate
		certsFound []CertObjInfo
		cert       *x509.Certificate
		certUri    *pkcs11uri.Pkcs11URI
	)

	module = pkcs11Signer.module
	certChain = pkcs11Signer.certChain
	certUri = pkcs11Signer.certUri

	if certChain != nil {
		return certChain, nil
	}

	if certUri == nil {
		return nil, errors.New("signer created using only certificate; " +
			"unable to get certificate chain")
	}

	// If there is currently no open session, then this method will open it.
	cert, err = pkcs11Signer.Certificate()
	if err != nil {
		return nil, err
	}

	chain = append(chain, cert)
	session = pkcs11Signer.session

	certsFound, err = getCertsInSession(module, 0, session, nil)
	if err != nil {
		return nil, err
	}

	for true {
		nextInChainFound := false
		for i, curCert := range certsFound {
			curLastCert := chain[len(chain)-1]
			if certIssues(curLastCert, curCert.cert) {
				nextInChainFound = true
				chain = append(chain, curCert.cert)

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

	pkcs11Signer.certChain = chain

	return chain, err
}

// Checks whether the private key and certificate are associated with each other
func checkPrivateKeyMatchesCert(module *pkcs11.Ctx, session pkcs11.SessionHandle, keyType uint, alwaysAuth uint, pinPkcs11 string, privateKeyHandle pkcs11.ObjectHandle, certificate *x509.Certificate, manufacturerId string) (string, bool) {
	var digestSuffix []byte
	publicKey := certificate.PublicKey
	ecdsaPublicKey, isEcKey := publicKey.(*ecdsa.PublicKey)
	if isEcKey {
		digestSuffixArr := sha256.Sum256(append([]byte("IAM RA"), elliptic.Marshal(ecdsaPublicKey, ecdsaPublicKey.X, ecdsaPublicKey.Y)...))
		digestSuffix = digestSuffixArr[:]
		if keyType != pkcs11.CKK_EC {
			return "", false
		}
	}

	rsaPublicKey, isRsaKey := publicKey.(*rsa.PublicKey)
	if isRsaKey {
		digestSuffixArr := sha256.Sum256(append([]byte("IAM RA"), x509.MarshalPKCS1PublicKey(rsaPublicKey)...))
		digestSuffix = digestSuffixArr[:]
		if keyType != pkcs11.CKK_RSA {
			return "", false
		}
	}
	// "AWS Roles Anywhere Credential Helper PKCS11 Test" || PKCS11_TEST_VERSION ||
	// MANUFACTURER_ID || SHA256("IAM RA" || PUBLIC_KEY_BYTE_ARRAY)
	digest := "AWS Roles Anywhere Credential Helper PKCS11 Test" +
		strconv.Itoa(int(PKCS11_TEST_VERSION)) + manufacturerId + string(digestSuffix)
	digestBytes := []byte(digest)
	hash := sha256.Sum256(digestBytes)

	contextSpecificPin, signature, err := signHelper(module, session, privateKeyHandle, alwaysAuth, pinPkcs11, keyType, digestBytes, crypto.SHA256)
	if err != nil {
		return "", false
	}

	if isEcKey {
		valid := ecdsa.VerifyASN1(ecdsaPublicKey, hash[:], signature)
		return contextSpecificPin, valid
	}

	if isRsaKey {
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signature)
		return contextSpecificPin, err == nil
	}

	return "", false
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
	var (
		module             *pkcs11.Ctx
		certObj            CertObjInfo
		session            pkcs11.SessionHandle
		loggedIn           bool
		privateKeyHandle   pkcs11.ObjectHandle
		keyType            uint
		contextSpecificPin string
		userPin            string
		alwaysAuth         uint
		certSlotNr         uint
		certUri            *pkcs11uri.Pkcs11URI
		keyUri             *pkcs11uri.Pkcs11URI
		slots              []SlotIdInfo
		certSlot           SlotIdInfo
	)

	module, err = initializePKCS11Module(libPkcs11)
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
		userPin, _ = certUri.GetQueryAttribute("pin-value", false)
		certSlot, slots, session, loggedIn, certObj, err = getCertificate(module, certUri, userPin)
		if err != nil {
			goto fail
		}
		certSlotNr = certSlot.id
		certificate = certObj.cert
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
	userPin, _ = keyUri.GetQueryAttribute("pin-value", false)

	// If the certificate URI wasn't provided, enumerate slots.
	if certificateId == "" {
		slots, err = enumerateSlotsInPKCS11Module(module)
		if err != nil {
			goto fail
		}
	}

	session, keyType, privateKeyHandle, alwaysAuth, contextSpecificPin, err = getPKCS11Key(module, session, loggedIn, certUri, keyUri, certSlotNr, certObj, userPin, contextSpecificPin, slots)
	if err != nil {
		goto fail
	}
	loggedIn = true

	switch keyType {
	case pkcs11.CKK_EC:
		signingAlgorithm = aws4_x509_ecdsa_sha256
	case pkcs11.CKK_RSA:
		signingAlgorithm = aws4_x509_rsa_sha256
	default:
		return nil, "", errors.New("unsupported algorithm")
	}

	return &PKCS11Signer{certObj, nil, module, userPin, alwaysAuth, contextSpecificPin, certUri, keyUri, session, keyType, privateKeyHandle, loggedIn, certSlotNr, slots}, signingAlgorithm, nil

fail:
	if module != nil {
		if session != 0 {
			if loggedIn {
				module.Logout(session)
			}
			module.CloseSession(session)
		}
		module.Finalize()
		module.Destroy()
	}

	return nil, "", err
}

// Does PIN prompting until the password has been received.
// This method is used both for prompting for the user PIN and the
// context-specific PIN. Note that finalAuthErrMsg should contain a
// `%s` so that the actual error message can be included.
func pkcs11PasswordPrompt(module *pkcs11.Ctx, session pkcs11.SessionHandle, userType uint, passwordName string, finalAuthErrMsg string) (string, error) {
	var pin string

	parseErrMsg := fmt.Sprintf("unable to read PKCS#11 %s", passwordName)
	prompt := fmt.Sprintf("Please enter your %s", passwordName)

	ttyPath := "/dev/tty"
	if runtime.GOOS == "windows" {
		ttyPath = "CON"
	}

	ttyFile, err := os.OpenFile(ttyPath, os.O_RDWR, 0)
	if err != nil {
		return "", errors.New(parseErrMsg)
	}
	defer ttyFile.Close()

	for true {
		pin, err = GetPassword(ttyFile, prompt, parseErrMsg)
		if err != nil && err.Error() == parseErrMsg {
			continue
		}

		err = module.Login(session, userType, pin)
		if err != nil {
			// Loop on failure in case the user mistyped their PIN.
			if strings.Contains(err.Error(), "CKR_PIN_INCORRECT") {
				prompt = fmt.Sprintf("Incorrect %s. Please re-enter your %s:", passwordName, passwordName)
				continue
			}
			return "", fmt.Errorf(finalAuthErrMsg, err.Error())
		}
		return pin, nil
	}

	// Code should never reach here
	return "", fmt.Errorf("unexpected error when prompting for %s", passwordName)
}

// Prompts the user for their password
func GetPassword(ttyFile *os.File, prompt string, parseErrMsg string) (string, error) {
	fmt.Fprintln(ttyFile, prompt)
	passwordBytes, err := term.ReadPassword(int(ttyFile.Fd()))
	if err != nil {
		return "", errors.New(parseErrMsg)
	}

	password := string(passwordBytes[:])
	strings.Replace(password, "\r", "", -1) // Remove CR
	return password, nil
}
