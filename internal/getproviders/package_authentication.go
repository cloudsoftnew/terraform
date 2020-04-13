package getproviders

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
	openpgpArmor "golang.org/x/crypto/openpgp/armor"
	openpgpErrors "golang.org/x/crypto/openpgp/errors"
)

type packageAuthenticationResult int

const (
	verifiedChecksum packageAuthenticationResult = iota
	hashicorpProvider
	partnerProvider
	communityProvider
)

// FIXME docs
type PackageAuthenticationResult struct {
	result  packageAuthenticationResult
	Warning string
}

func (t *PackageAuthenticationResult) String() string {
	if t == nil {
		return "Unauthenticated"
	}
	return []string{
		"verified checksum",
		"HashiCorp provider",
		"Partner provider",
		"community provider",
	}[t.result]
}

// FIXME docs
type SigningKey struct {
	ASCIIArmor     string `json:"ascii_armor"`
	TrustSignature string `json:"trust_signature"`
}

// PackageAuthentication is an interface implemented by the optional package
// authentication implementations a source may include on its PackageMeta
// objects.
//
// A PackageAuthentication implementation is responsible for authenticating
// that a package is what its distributor intended to distribute and that it
// has not been tampered with.
type PackageAuthentication interface {
	// AuthenticatePackage takes the metadata about the package as returned
	// by its original source, and also the "localLocation" where it has
	// been staged for local inspection (which may or may not be the same
	// as the original source location) and returns an error if the
	// authentication checks fail.
	//
	// The localLocation is guaranteed not to be a PackageHTTPURL: a
	// remote package will always be staged locally for inspection first.
	AuthenticatePackage(meta PackageMeta, localLocation PackageLocation) (*PackageAuthenticationResult, error)
}

type packageAuthenticationAll []PackageAuthentication

// PackageAuthenticationAll combines several authentications together into a
// single check value, which passes only if all of the given ones pass.
//
// The checks are processed in the order given, so a failure of an earlier
// check will prevent execution of a later one.
func PackageAuthenticationAll(checks ...PackageAuthentication) PackageAuthentication {
	return packageAuthenticationAll(checks)
}

func (checks packageAuthenticationAll) AuthenticatePackage(meta PackageMeta, localLocation PackageLocation) (*PackageAuthenticationResult, error) {
	var authResult *PackageAuthenticationResult
	for _, check := range checks {
		var err error
		authResult, err = check.AuthenticatePackage(meta, localLocation)
		if err != nil {
			return authResult, err
		}
	}
	return authResult, nil
}

type archiveHashAuthentication struct {
	WantSHA256Sum [sha256.Size]byte
}

// NewArchiveChecksumAuthentication returns a PackageAuthentication
// implementation that checks that the original distribution archive matches
// the given hash.
//
// This authentication is suitable only for PackageHTTPURL and
// PackageLocalArchive source locations, because the unpacked layout
// (represented by PackageLocalDir) does not retain access to the original
// source archive. Therefore this authenticator will return an error if its
// given localLocation is not PackageLocalArchive.
func NewArchiveChecksumAuthentication(wantSHA256Sum [sha256.Size]byte) PackageAuthentication {
	return archiveHashAuthentication{wantSHA256Sum}
}

func (a archiveHashAuthentication) AuthenticatePackage(meta PackageMeta, localLocation PackageLocation) (*PackageAuthenticationResult, error) {
	archiveLocation, ok := localLocation.(PackageLocalArchive)
	if !ok {
		// A source should not use this authentication type for non-archive
		// locations.
		return nil, fmt.Errorf("cannot check archive hash for non-archive location %s", localLocation)
	}

	f, err := os.Open(string(archiveLocation))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return nil, err
	}

	gotHash := h.Sum(nil)
	if !bytes.Equal(gotHash, a.WantSHA256Sum[:]) {
		return nil, fmt.Errorf("archive has incorrect SHA-256 checksum %x (expected %x)", gotHash, a.WantSHA256Sum[:])
	}
	return &PackageAuthenticationResult{result: verifiedChecksum}, nil
}

type matchingChecksumAuthentication struct {
	Document      []byte
	Filename      string
	WantSHA256Sum [sha256.Size]byte
}

// NewMatchingChecksumAuthentication FIXME
func NewMatchingChecksumAuthentication(document []byte, filename string, wantSHA256Sum [sha256.Size]byte) PackageAuthentication {
	return matchingChecksumAuthentication{
		Document:      document,
		Filename:      filename,
		WantSHA256Sum: wantSHA256Sum,
	}
}

func (m matchingChecksumAuthentication) AuthenticatePackage(meta PackageMeta, location PackageLocation) (*PackageAuthenticationResult, error) {
	if _, ok := meta.Location.(PackageHTTPURL); !ok {
		// A source should not use this authentication type for non-HTTP
		// source locations.
		return nil, fmt.Errorf("cannot verify matching checksum for non-HTTP location %s", meta.Location)
	}

	// Find the checksum in the list with matching filename. The document is
	// in the form "0123456789abcdef filename.zip".
	filename := []byte(m.Filename)
	var checksum []byte
	for _, line := range bytes.Split(m.Document, []byte("\n")) {
		parts := bytes.Fields(line)
		if len(parts) > 1 && bytes.Equal(parts[1], filename) {
			checksum = parts[0]
			break
		}
	}
	if checksum == nil {
		return nil, fmt.Errorf("checksum list has no SHA-256 hash for %q", m.Filename)
	}

	// Decode the ASCII checksum into a byte array for comparison.
	var gotSHA256Sum [sha256.Size]byte
	if _, err := hex.Decode(gotSHA256Sum[:], checksum); err != nil {
		return nil, fmt.Errorf("checksum list has invalid SHA256 hash %q: %s", string(checksum), err)
	}

	// If thee checksums don't match, authentication fails.
	if !bytes.Equal(gotSHA256Sum[:], m.WantSHA256Sum[:]) {
		return nil, fmt.Errorf("checksum list has unexpected SHA-256 hash %x (expected %x)", gotSHA256Sum, m.WantSHA256Sum[:])
	}

	// Success! But this doesn't result in any real authentication, only a
	// lack of authentication errors, so we return a nil result.
	return nil, nil
}

type signatureAuthentication struct {
	Document  []byte
	Signature []byte
	Keys      []SigningKey
}

// NewSignatureAuthentication returns a PackageAuthentication implementation
// that verifies the cryptographic signature for a package against a given key.
func NewSignatureAuthentication(document, signature []byte, keys []SigningKey) PackageAuthentication {
	return signatureAuthentication{
		Document:  document,
		Signature: signature,
		Keys:      keys,
	}
}

func (s signatureAuthentication) AuthenticatePackage(meta PackageMeta, location PackageLocation) (*PackageAuthenticationResult, error) {
	if _, ok := location.(PackageLocalArchive); !ok {
		// A source should not use this authentication type for non-archive
		// locations.
		return nil, fmt.Errorf("cannot check archive hash for non-archive location %s", location)
	}

	if _, ok := meta.Location.(PackageHTTPURL); !ok {
		// A source should not use this authentication type for non-HTTP source
		// locations.
		return nil, fmt.Errorf("cannot check archive hash for non-HTTP location %s", meta.Location)
	}

	// Attempt to verify the signature using each of the keys returned by the
	// registry. Note: currently the registry only returns one key, but this
	// may change in the future. We must check each key in turn to find the
	// matching signing entity before proceeding.
	var signingKey *SigningKey
	for _, key := range s.Keys {
		keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key.ASCIIArmor))
		if err != nil {
			return nil, err
		}

		_, err = openpgp.CheckDetachedSignature(keyring, bytes.NewReader(s.Document), bytes.NewReader(s.Signature))

		// If the signature issuer does not match the the key, keep trying the
		// rest of the provided keys.
		if err == openpgpErrors.ErrUnknownIssuer {
			continue
		}

		// Any other signature error is terminal.
		if err != nil {
			return nil, err
		}

		signingKey = &key
		break
	}

	// If none of the provided keys issued the signature, this package is
	// unsigned. This is currently a terminal authentication error.
	if signingKey == nil {
		return nil, fmt.Errorf("Authentication signature from unknown issuer")
	}

	// Verify the signature using the HashiCorp public key. If this succeeds,
	// this is an official provider.
	hashicorpKeyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(HashicorpPublicKey))
	if err != nil {
		return nil, fmt.Errorf("Error creating HashiCorp keyring: %s", err)
	}
	_, err = openpgp.CheckDetachedSignature(hashicorpKeyring, bytes.NewReader(s.Document), bytes.NewReader(s.Signature))
	if err == nil {
		return &PackageAuthenticationResult{result: hashicorpProvider}, nil
	}

	// If the signing key has a trust signature, attempt to verify it with the
	// HashiCorp partners public key.
	if signingKey.TrustSignature != "" {
		hashicorpPartnersKeyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(HashicorpPartnersKey))
		if err != nil {
			return nil, fmt.Errorf("Error creating HashiCorp Partners keyring: %s", err)
		}

		authorKey, err := openpgpArmor.Decode(strings.NewReader(signingKey.ASCIIArmor))
		if err != nil {
			return nil, err
		}

		trustSignature, err := openpgpArmor.Decode(strings.NewReader(signingKey.TrustSignature))
		if err != nil {
			return nil, err
		}

		_, err = openpgp.CheckDetachedSignature(hashicorpPartnersKeyring, authorKey.Body, trustSignature.Body)
		if err != nil {
			return nil, fmt.Errorf("Error verifying trust signature: %s", err)
		}

		return &PackageAuthenticationResult{result: partnerProvider}, nil
	}

	// We have a valid signature, but it's not from the HashiCorp key, and it
	// also isn't a trusted partner. This is a community provider.
	return &PackageAuthenticationResult{
		result:  communityProvider,
		Warning: communityProviderWarning,
	}, nil
}

const communityProviderWarning = `community providers are not trusted by HashiCorp. Use at your own risk.`
