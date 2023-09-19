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
	"log"
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
	id         []byte
	label      []byte
	cert       *x509.Certificate
	certObject pkcs11.ObjectHandle
}

// In our list of keys, we want to remember the CKA_ID/CKA_LABEL too.
type KeyObjInfo struct {
	id        []byte
	label     []byte
	keyObject pkcs11.ObjectHandle
}

// Used to enumerate slots with all token/slot info for matching.
type SlotIdInfo struct {
	id      uint
	info    pkcs11.SlotInfo
	tokInfo pkcs11.TokenInfo
}

type PKCS11Signer struct {
	cert               *x509.Certificate
	certChain          []*x509.Certificate
	module             *pkcs11.Ctx
	userPin            string
	alwaysAuth         uint
	contextSpecificPin string
	certUri            *pkcs11uri.Pkcs11URI
	keyUri             *pkcs11uri.Pkcs11URI
	reusePin           bool
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
			if Debug {
				log.Printf("unable to get slot info for slot %d"+
					" (%s)\n", slotId, slotErr)
			}
			continue
		}
		slotIdInfo.tokInfo, slotErr = module.GetTokenInfo(slotId)
		if slotErr != nil {
			if Debug {
				log.Printf("unable to get token info for slot %d"+
					" (%s)\n", slotId, slotErr)
			}
			continue
		}

		slots = append(slots, slotIdInfo)
	}

	return slots, nil
}

// Return true if the URI specifies the attribute and it *doesn't* match.
func mismatchAttr(uri *pkcs11uri.Pkcs11URI, attr string, val string) bool {
	var (
		uriVal string
		ok     bool
	)

	uriVal, ok = uri.GetPathAttribute(attr, false)
	return ok && uriVal != val
}

// Return the set of slots which match the given URI.
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

// Convert the object-related fields in a URI to []*pkcs11.Attribute for FindObjectsInit().
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

	// Convert the URI into a template for FindObjectsInit().
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

		certObj.certObject = certObject

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
// will be left open and returned. The session may also be logged in to in the
// case that the certificate being searched for could only be found after
// logging in to the token.
//
// NB: It's generally only looking for *one* cert to use. If you want
// `p11tool --list-certificates`, use that instead.
func getMatchingCerts(module *pkcs11.Ctx, slots []SlotIdInfo, uri *pkcs11uri.Pkcs11URI, userPin string, single bool) (matchedSlot SlotIdInfo, session pkcs11.SessionHandle, loggedIn bool, matchingCerts []CertObjInfo, err error) {
	var (
		errNoMatchingCerts error
	)

	errNoMatchingCerts = errors.New("no matching certificates")

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
			if Debug {
				log.Printf("unable to open session in slot %d"+
					" (%s)\n", slot.id, err)
			}
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
				goto skipCloseSession
			}
		}
		module.CloseSession(curSession)
	skipCloseSession:
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
	if len(slots) == 1 {
		if userPin != "" {
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
		} else {
			err = errors.New("one matching slot, but no user PIN provided")
			goto fail
		}
	} else if len(slots) == 0 {
		err = errors.New("no matching slots")
		goto fail
	} else {
		err = errors.New("multiple matching slots")
		goto fail
	}

foundCert:
	if single && len(matchingCerts) > 1 {
		err = errors.New("multiple matching certificates")
		goto fail
	}

	// Exactly one matching certificate after logging in to the appropriate token
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
	var module *pkcs11.Ctx

	module = pkcs11Signer.module

	if module != nil {
		module.Finalize()
		module.Destroy()
	}

	pkcs11Signer.module = nil
}

// Does PIN prompting until the password has been received.
// This method is used both for prompting for the user PIN and the
// context-specific PIN. Note that finalAuthErrMsg should contain a
// `%s` so that the actual error message can be included.
func pkcs11PasswordPrompt(module *pkcs11.Ctx, session pkcs11.SessionHandle, userType uint, passwordName string, finalAuthErrMsg string) (pinValue string, err error) {
	var (
		parseErrMsg  string
		pin          string
		prompt       string
		ttyReadPath  string
		ttyWritePath string
		ttyReadFile  *os.File
		ttyWriteFile *os.File
	)

	parseErrMsg = fmt.Sprintf("unable to read PKCS#11 %s", passwordName)
	prompt = fmt.Sprintf("Please enter your %s:", passwordName)

	ttyReadPath = "/dev/tty"
	ttyWritePath = ttyReadPath
	if runtime.GOOS == "windows" {
		ttyReadPath = "CONIN$"
		ttyWritePath = "CONOUT$"
	}

	ttyReadFile, err = os.OpenFile(ttyReadPath, os.O_RDWR, 0)
	if err != nil {
		return "", errors.New(parseErrMsg)
	}
	defer ttyReadFile.Close()

	ttyWriteFile, err = os.OpenFile(ttyWritePath, os.O_WRONLY, 0)
	if err != nil {
		return "", errors.New(parseErrMsg)
	}
	defer ttyWriteFile.Close()

	for true {
		pin, err = GetPassword(ttyReadFile, ttyWriteFile, prompt, parseErrMsg)
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

	// The code should never reach here.
	return "", fmt.Errorf("unexpected error when prompting for %s", passwordName)
}

// Prompts the user for their password
func GetPassword(ttyReadFile *os.File, ttyWriteFile *os.File, prompt string, parseErrMsg string) (string, error) {
	fmt.Fprintln(ttyWriteFile, prompt)
	passwordBytes, err := term.ReadPassword(int(ttyReadFile.Fd()))
	if err != nil {
		return "", errors.New(parseErrMsg)
	}

	password := string(passwordBytes[:])
	strings.Replace(password, "\r", "", -1) // Remove CR
	return password, nil
}

// Helper function to sign a digest using a PKCS#11 private key handle.
func signHelper(module *pkcs11.Ctx, session pkcs11.SessionHandle, privateKeyObj KeyObjInfo, slot SlotIdInfo, userPin string, alwaysAuth uint, contextSpecificPin string, reusePin bool, keyType uint, digest []byte, hashFunc crypto.Hash) (_contextSpecificPin string, signature []byte, err error) {
	// XXX: If you use this outside the context of IAM RA, be aware that
	// you'll want to use something other than SHA256 in many cases.
	// For TLSv1.3 the hash needs to precisely match the bit size of the
	// curve, IIRC. And you'll need RSA-PSS too. You might find that
	// ThalesIgnite/crypto11 has some of that.
	// e.g. https://github.com/ThalesIgnite/crypto11/blob/master/rsa.go#L230
	var (
		mechanism uint
		keyUri    *pkcs11uri.Pkcs11URI
		keyUriStr string
	)

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

	err = module.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}, privateKeyObj.keyObject)
	if err != nil {
		return "", nil, fmt.Errorf("signing initiation failed (%s)", err.Error())
	}

	if alwaysAuth != 0 {
		// Set the value for the context-specific PIN used to do the signing
		// operation with this key. If the context-specific PIN wasn't specified
		// in the input, and the "reuse PIN" option was set, try to use the
		// user PIN as the context-specific PIN.
		if contextSpecificPin == "" && userPin != "" && reusePin {
			contextSpecificPin = userPin
		}
		if contextSpecificPin != "" {
			err = module.Login(session, pkcs11.CKU_CONTEXT_SPECIFIC, contextSpecificPin)
			if err == nil {
				goto afterContextSpecificLogin
			} else {
				if Debug {
					log.Printf("user re-authentication attempt failed (%s)\n", err.Error())
				}
			}
		}

		// If the context-specific PIN couldn't be derived, prompt the user for
		// the context-specific PIN for this object.
		keyUri = pkcs11uri.New()
		keyUri.AddPathAttribute("model", slot.tokInfo.Model)
		keyUri.AddPathAttribute("manufacturer", slot.tokInfo.ManufacturerID)
		keyUri.AddPathAttribute("serial", slot.tokInfo.SerialNumber)
		keyUri.AddPathAttribute("slot-description", slot.info.SlotDescription)
		keyUri.AddPathAttribute("slot-manufacturer", slot.info.ManufacturerID)
		if privateKeyObj.id != nil {
			keyUri.AddPathAttribute("id", string(privateKeyObj.id[:]))
		}
		if privateKeyObj.label != nil {
			keyUri.AddPathAttribute("object", string(privateKeyObj.label[:]))
		}
		keyUri.AddPathAttribute("type", "private")
		keyUriStr, err = keyUri.Format() // nosemgrep
		if err != nil {
			keyUriStr = ""
		}
		passwordName := "context-specific PIN"
		if keyUriStr != "" {
			passwordName = fmt.Sprintf("context-specific PIN for private key object (%s)", keyUriStr)
		}
		finalAuthErrMsg := "user re-authentication failed (%s)"
		contextSpecificPin, err = pkcs11PasswordPrompt(module, session, pkcs11.CKU_CONTEXT_SPECIFIC, passwordName, finalAuthErrMsg)
		if err != nil {
			return "", nil, err
		}
	}

afterContextSpecificLogin:
	sig, err := module.Sign(session, digest)
	if err != nil {
		return contextSpecificPin, nil, fmt.Errorf("signing failed (%s)", err.Error())
	}

	// Yay, we have to do the ASN.1 encoding of the R, S values ourselves.
	if mechanism == pkcs11.CKM_ECDSA {
		sig, err = encodeEcdsaSigValue(sig)
		if err != nil {
			return contextSpecificPin, nil, err
		}
	}

	return contextSpecificPin, sig, nil
}

// Gets a handle to the private key object (along with some other information
// that may need to be saved).
func getPKCS11Key(module *pkcs11.Ctx, session pkcs11.SessionHandle, loggedIn bool, certUri *pkcs11uri.Pkcs11URI, keyUri *pkcs11uri.Pkcs11URI, noKeyUri bool, certSlotNr uint, certObj CertObjInfo, userPin string, contextSpecificPin string, reusePin bool, slots []SlotIdInfo) (_session pkcs11.SessionHandle, _userPin string, _keyUri *pkcs11uri.Pkcs11URI, keyType uint, privateKeyObj KeyObjInfo, slot SlotIdInfo, alwaysAuth uint, _contextSpecificPin string, err error) {
	var (
		keySlot            SlotIdInfo
		manufacturerId     string
		templatePrivateKey []*pkcs11.Attribute
		privateKeyObjects  []pkcs11.ObjectHandle
		keyAttributes      []*pkcs11.Attribute
	)

	if keyUri == nil {
		keyUri = certUri
		noKeyUri = true
	}

	if userPin == "" {
		userPin, _ = keyUri.GetQueryAttribute("pin-value", false)
	}

	// This time we're looking for a *single* slot, as we (presumably)
	// will have to log in to access the key.
	slots = matchSlots(slots, keyUri)
	if len(slots) == 1 {
		if certSlotNr != slots[0].id {
			keySlot = slots[0]
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
		if Debug {
			log.Printf("Found %d matching slots for the PKCS#11 key\n", len(slots))
		}
		// If the URI matched multiple slots *but* one of them is the
		// one (certSlotNr) that the certificate was found in, then use
		// that.
		for _, slot := range slots {
			if certSlotNr == slot.id {
				keySlot = slot
				manufacturerId = slot.info.ManufacturerID
				goto got_slot
			}
		}
		err = errors.New("Could not identify unique slot for PKCS#11 key")
		goto fail
	}

got_slot:
	if session == 0 {
		session, err = module.OpenSession(keySlot.id, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKS_RO_PUBLIC_SESSION)
	}
	if err != nil {
		goto fail
	}

	// And *now* we fall back to prompting the user for a PIN if necessary.
	if !loggedIn {
		if userPin == "" {
			passwordName := "user PIN"
			finalAuthErrMsg := "user authentication failed (%s)"
			userPin, err = pkcs11PasswordPrompt(module, session, pkcs11.CKU_USER, passwordName, finalAuthErrMsg)
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

		var curPrivateKeyObj KeyObjInfo
		curPrivateKeyObj.keyObject = curPrivateKeyHandle

		// Fetch the CKA_ID and CKA_LABEL of the current private key object, so
		// that more specific attributes can be used to identify the private key
		// when prompting for a context-specifc PIN (assuming the CKA_ALWAYS_AUTHENTICATE
		// attribute is set on the private key object).
		keyAttributes[0] = pkcs11.NewAttribute(pkcs11.CKA_ID, 0)
		keyAttributes, err = module.GetAttributeValue(session, curPrivateKeyHandle, keyAttributes)
		if err == nil {
			curPrivateKeyObj.id = keyAttributes[0].Value
		}

		keyAttributes[0] = pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0)
		keyAttributes, err = module.GetAttributeValue(session, curPrivateKeyHandle, keyAttributes)
		if err == nil {
			curPrivateKeyObj.label = keyAttributes[0].Value
		}

		if certObj.cert == nil {
			if len(privateKeyObjects) == 1 {
				privateKeyObj = curPrivateKeyObj
				break
			} else {
				err = errors.New("multiple matching private keys, but" +
					" no certificate provided to match with")
				goto fail
			}
		}

		var curContextSpecificPin string
		privateKeyMatchesCert := false
		curContextSpecificPin, privateKeyMatchesCert = checkPrivateKeyMatchesCert(module, session, keyType, userPin, alwaysAuth, "", reusePin, curPrivateKeyObj, keySlot, certObj.cert, manufacturerId)
		if privateKeyMatchesCert {
			privateKeyObj = curPrivateKeyObj
			contextSpecificPin = curContextSpecificPin
			break
		}
	}

	if privateKeyObj.keyObject == 0 {
		/* "If the key is not found and the original search was by
		 * CKA_LABEL of the certificate, then repeat the search using
		 * the CKA_ID of the certificate that was actually found, but
		 * not requiring a CKA_LABEL match."
		 *
		 * http://david.woodhou.se/draft-woodhouse-cert-best-practice.html#rfc.section.8.2
		 */
		if certObj.cert != nil {
			if noKeyUri {
				_, keyHadLabel := keyUri.GetPathAttribute("object", false)
				if keyHadLabel {
					if Debug {
						log.Println("unable to find private key with CKA_LABEL;" +
							" repeating the search using CKA_ID of the certificate" +
							" without requiring a CKA_LABEL match")
					}
					keyUri.RemovePathAttribute("object")
					keyUri.SetPathAttribute("id", escapeAll(certObj.id))
					goto retry_search
				}
			}
		}

		err = errors.New("unable to find matching private key")
		goto fail
	}

	// So that hunting for the key can be more efficient in the future,
	// return a key URI that has CKA_ID and CKA_LABEL appropriately set.
	if privateKeyObj.id != nil {
		keyUri.SetPathAttribute("id", escapeAll(privateKeyObj.id))
	}
	if privateKeyObj.label != nil {
		keyUri.SetPathAttribute("object", escapeAll(privateKeyObj.label))
	}

	return session, userPin, keyUri, keyType, privateKeyObj, keySlot, alwaysAuth, contextSpecificPin, nil

fail:
	return 0, "", nil, 0, KeyObjInfo{}, SlotIdInfo{}, 0, "", err
}

// Gets the certificate in a token, given the URI that identifies the
// certificate. This method also optionally takes in a user PIN, which is
// only used (and prompted for, if not given and needed) if the token has to be
// logged in to, in order to obtain the certificate.
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
		privateKeyObj      KeyObjInfo
		keySlot            SlotIdInfo
		keyType            uint
		certSlotNr         uint
		certObj            CertObjInfo
		slots              []SlotIdInfo
		loggedIn           bool
		reusePin           bool
		alwaysAuth         uint
		certSlot           SlotIdInfo
	)

	hashFunc := opts.HashFunc()

	module = pkcs11Signer.module
	userPin = pkcs11Signer.userPin
	alwaysAuth = pkcs11Signer.alwaysAuth
	contextSpecificPin = pkcs11Signer.contextSpecificPin
	certUri = pkcs11Signer.certUri
	keyUri = pkcs11Signer.keyUri
	reusePin = pkcs11Signer.reusePin

	// If a PKCS#11 URI was provided for the certificate, use it.
	if certUri != nil {
		certSlot, slots, session, loggedIn, certObj, err = getCertificate(module, certUri, userPin)
		if err != nil {
			goto cleanUp
		}
		certSlotNr = certSlot.id
	}

	// Otherwise, if the certificate's PKCS#11 URI wasn't provided, enumerate slots.
	if certUri == nil {
		slots, err = enumerateSlotsInPKCS11Module(module)
		if err != nil {
			goto cleanUp
		}
	}

	session, userPin, keyUri, keyType, privateKeyObj, keySlot, alwaysAuth, contextSpecificPin, err = getPKCS11Key(module, session, loggedIn, certUri, keyUri, false, certSlotNr, certObj, userPin, contextSpecificPin, reusePin, slots)
	if err != nil {
		goto cleanUp
	}

	contextSpecificPin, signature, err = signHelper(module, session, privateKeyObj, keySlot, userPin, alwaysAuth, contextSpecificPin, reusePin, keyType, digest, hashFunc)
	if err != nil {
		goto cleanUp
	} else {
		pkcs11Signer.contextSpecificPin = contextSpecificPin
	}

	// Note that the session should be logged out of and closed even if there
	// are no errors after the signing operation.
cleanUp:
	if session != 0 {
		if loggedIn {
			module.Logout(session)
		}
		module.CloseSession(session)
	}

	return signature, err
}

// Gets the *x509.Certificate associated with this PKCS11Signer.
func (pkcs11Signer *PKCS11Signer) Certificate() (cert *x509.Certificate, err error) {
	// If there was a certificate chain associated with this Signer, it
	// should've been saved before.
	cert = pkcs11Signer.cert

	// If the certificate was saved, return it.
	if cert != nil {
		return cert, nil
	}

	return nil, errors.New("no certificate associated with signer")
}

// Checks whether the first certificate issues the second.
func certIssues(issuer *x509.Certificate, candidate *x509.Certificate) bool {
	roots := x509.NewCertPool()
	roots.AddCert(issuer)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err := candidate.Verify(opts)
	return err != nil
}

// Gets the certificate chain from the given session. Certificates in the
// chain are obtained through public key signature verification.
func getCertificateChain(module *pkcs11.Ctx, session pkcs11.SessionHandle, cert *x509.Certificate) (certChain []*x509.Certificate, err error) {
	var (
		certsFound []CertObjInfo
	)

	// The certificate chain starts with the passed in end-entity certificate.
	certChain = append(certChain, cert)

	certsFound, err = getCertsInSession(module, 0, session, nil)
	if err != nil {
		return nil, err
	}

	for true {
		nextInChainFound := false
		for i, curCert := range certsFound {
			lastCertChainCert := certChain[len(certChain)-1]
			if certIssues(curCert.cert, lastCertChainCert) {
				nextInChainFound = true
				certChain = append(certChain, curCert.cert)

				// Remove current cert, so that it won't be iterated again.
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

	return certChain, err
}

// Gets the certificate chain associated with this PKCS11Signer.
func (pkcs11Signer *PKCS11Signer) CertificateChain() (certChain []*x509.Certificate, err error) {
	certChain = pkcs11Signer.certChain

	// If there was a certificate chain associated with this Signer, it
	// should've been saved before.
	if certChain != nil {
		return certChain, nil
	}

	return nil, errors.New("no certificate chain associated with signer")
}

// Checks whether the private key and certificate are associated with each other.
func checkPrivateKeyMatchesCert(module *pkcs11.Ctx, session pkcs11.SessionHandle, keyType uint, userPin string, alwaysAuth uint, contextSpecificPin string, reusePin bool, privateKeyObj KeyObjInfo, keySlot SlotIdInfo, certificate *x509.Certificate, manufacturerId string) (string, bool) {
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

	contextSpecificPin, signature, err := signHelper(module, session, privateKeyObj, keySlot, userPin, alwaysAuth, "", reusePin, keyType, digestBytes, crypto.SHA256)
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

// Upper character hex digits needed for pct-encoding.
const hexchar = "0123456789ABCDEF"

// escapeAll pct-escapes all characters in the string.
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
// through a PKCS#11-compatible cryptographic device.
func GetPKCS11Signer(libPkcs11 string, cert *x509.Certificate, certChain []*x509.Certificate, privateKeyId string, certificateId string, reusePin bool) (signer Signer, signingAlgorithm string, err error) {
	var (
		module             *pkcs11.Ctx
		certObj            CertObjInfo
		session            pkcs11.SessionHandle
		loggedIn           bool
		keyType            uint
		contextSpecificPin string
		userPin            string
		alwaysAuth         uint
		certSlotNr         uint
		certUri            *pkcs11uri.Pkcs11URI
		keyUri             *pkcs11uri.Pkcs11URI
		slots              []SlotIdInfo
		certSlot           SlotIdInfo
		noKeyUri           bool
	)

	module, err = initializePKCS11Module(libPkcs11)
	if err != nil {
		goto fail
	}

	// If a PKCS#11 URI was provided for the certificate, find it.
	if cert == nil && certificateId != "" {
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
		cert = certObj.cert

		// So that hunting for the certificate can be more efficient in the future,
		// update the cert URI that has CKA_ID and CKA_VALUE appropriately set.
		crtAttributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, 0),
		}
		crtAttributes, err = module.GetAttributeValue(session, certObj.certObject, crtAttributes)
		if err == nil {
			certUri.SetPathAttribute("id", escapeAll(crtAttributes[0].Value))
		}

		crtAttributes[0] = pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0)
		crtAttributes, err = module.GetAttributeValue(session, certObj.certObject, crtAttributes)
		if err == nil {
			certUri.SetPathAttribute("object", escapeAll(crtAttributes[0].Value))
		}

		if certChain == nil {
			certChain, err = getCertificateChain(module, session, cert)
			if err != nil {
				goto fail
			}
		}
	} else if cert != nil {
		// Populate certObj, so that it can be used to find the matching private key.
		certObj = CertObjInfo{nil, nil, cert, 0}
	}

	// If an explicit private-key option was given, use it. Otherwise
	// we look in the same place as the certificate URI as directed by
	// http://david.woodhou.se/draft-woodhouse-cert-best-practice.html#rfc.section.8.2
	if privateKeyId != "" {
		keyUri = pkcs11uri.New()
		err = keyUri.Parse(privateKeyId)
		if err != nil {
			goto fail
		}
	} else {
		certUriStr, _ := certUri.Format()
		keyUri = pkcs11uri.New()
		keyUri.Parse(certUriStr)
		noKeyUri = true
	}
	if _userPin, ok := keyUri.GetQueryAttribute("pin-value", false); ok {
		userPin = _userPin
	}

	// If the certificate's PKCS#11 URI wasn't provided, enumerate slots.
	if certificateId == "" {
		slots, err = enumerateSlotsInPKCS11Module(module)
		if err != nil {
			goto fail
		}
	}

	session, userPin, keyUri, keyType, _, _, alwaysAuth, contextSpecificPin, err = getPKCS11Key(module, session, loggedIn, certUri, keyUri, noKeyUri, certSlotNr, certObj, userPin, "", reusePin, slots)
	if err != nil {
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

	if session != 0 {
		if loggedIn {
			module.Logout(session)
		}
		module.CloseSession(session)
	}

	return &PKCS11Signer{cert, certChain, module, userPin, alwaysAuth, contextSpecificPin, certUri, keyUri, reusePin}, signingAlgorithm, nil

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
