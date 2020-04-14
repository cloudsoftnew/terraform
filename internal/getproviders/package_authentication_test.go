package getproviders

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

func TestPackageAuthenticationResult(t *testing.T) {
	tests := []struct {
		result *PackageAuthenticationResult
		want   string
	}{
		{
			nil,
			"unauthenticated",
		},
		{
			&PackageAuthenticationResult{result: verifiedChecksum},
			"verified checksum",
		},
		{
			&PackageAuthenticationResult{result: hashicorpProvider},
			"HashiCorp provider",
		},
		{
			&PackageAuthenticationResult{result: partnerProvider},
			"Partner provider",
		},
		{
			&PackageAuthenticationResult{result: communityProvider},
			"community provider",
		},
	}
	for _, test := range tests {
		if got := test.result.String(); got != test.want {
			t.Errorf("wrong value: got %q, want %q", got, test.want)
		}
	}
}

// mockAuthentication is an implementation of the PackageAuthentication
// interface which returns fixed values. This is used to test the combining
// logic of PackageAuthenticationAll.
type mockAuthentication struct {
	result packageAuthenticationResult
	err    error
}

func (m mockAuthentication) AuthenticatePackage(meta PackageMeta, localLocation PackageLocation) (*PackageAuthenticationResult, error) {
	if m.err == nil {
		return &PackageAuthenticationResult{result: m.result}, nil
	} else {
		return nil, m.err
	}
}

var _ PackageAuthentication = (*mockAuthentication)(nil)

// If all authentications succeed, the returned result should come from the
// last authentication.
func TestPackageAuthenticationAll_success(t *testing.T) {
	result, err := PackageAuthenticationAll(
		&mockAuthentication{result: verifiedChecksum},
		&mockAuthentication{result: communityProvider},
	).AuthenticatePackage(PackageMeta{}, nil)

	want := PackageAuthenticationResult{result: communityProvider}
	if result == nil || *result != want {
		t.Errorf("wrong result: want %#v, got %#v", want, result)
	}
	if err != nil {
		t.Errorf("wrong err: got %#v, want nil", err)
	}
}

// If an authentication fails, its error should be returned along with a nil
// result.
func TestPackageAuthenticationAll_failure(t *testing.T) {
	someError := errors.New("some error")
	result, err := PackageAuthenticationAll(
		&mockAuthentication{result: verifiedChecksum},
		&mockAuthentication{err: someError},
		&mockAuthentication{result: communityProvider},
	).AuthenticatePackage(PackageMeta{}, nil)

	if result != nil {
		t.Errorf("wrong result: got %#v, want nil", result)
	}
	if err != someError {
		t.Errorf("wrong err: got %#v, want %#v", err, someError)
	}
}

// Archive checksum authentication success requires a file fixture and a
// known-good SHA256 hash. The result should be "verified checksum".
func TestArchiveChecksumAuthentication_success(t *testing.T) {
	// PackageMeta is unused by this authentication mechanism
	// FIXME: and really by all the others, so let's remove it from the call
	// signature in a later commit
	meta := PackageMeta{}

	// Location must be a PackageLocalArchive path
	location := PackageLocalArchive("testdata/filesystem-mirror/registry.terraform.io/hashicorp/null/terraform-provider-null_2.1.0_linux_amd64.zip")

	// Known-good SHA256 hash for this archive
	wantSHA256Sum := [sha256.Size]byte{
		0x4f, 0xb3, 0x98, 0x49, 0xf2, 0xe1, 0x38, 0xeb,
		0x16, 0xa1, 0x8b, 0xa0, 0xc6, 0x82, 0x63, 0x5d,
		0x78, 0x1c, 0xb8, 0xc3, 0xb2, 0x59, 0x01, 0xdd,
		0x5a, 0x79, 0x2a, 0xde, 0x97, 0x11, 0xf5, 0x01,
	}

	auth := NewArchiveChecksumAuthentication(wantSHA256Sum)
	result, err := auth.AuthenticatePackage(meta, location)

	wantResult := PackageAuthenticationResult{result: verifiedChecksum}
	if result == nil || *result != wantResult {
		t.Errorf("wrong result: got %#v, want %#v", result, wantResult)
	}
	if err != nil {
		t.Errorf("wrong err: got %s, want nil", err)
	}
}

// Archive checksum authentication can fail for various reasons. These test
// cases are almost exhaustive, missing only an io.Copy error which is
// difficult to induce.
func TestArchiveChecksumAuthentication_failure(t *testing.T) {
	tests := map[string]struct {
		location PackageLocation
		err      string
	}{
		"missing file": {
			PackageLocalArchive("testdata/no-package-here.zip"),
			"open testdata/no-package-here.zip: no such file or directory",
		},
		"checksum mismatch": {
			PackageLocalArchive("testdata/filesystem-mirror/registry.terraform.io/hashicorp/null/terraform-provider-null_2.1.0_linux_amd64.zip"),
			"archive has incorrect SHA-256 checksum 4fb39849f2e138eb16a18ba0c682635d781cb8c3b25901dd5a792ade9711f501 (expected 0000000000000000000000000000000000000000000000000000000000000000)",
		},
		"invalid location": {
			PackageLocalDir("testdata/filesystem-mirror/tfe.example.com/AwesomeCorp/happycloud/0.1.0-alpha.2/darwin_amd64"),
			"cannot check archive hash for non-archive location testdata/filesystem-mirror/tfe.example.com/AwesomeCorp/happycloud/0.1.0-alpha.2/darwin_amd64",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// PackageMeta is unused by this authentication mechanism
			// FIXME: and really by all the others, so let's remove it from the call
			// signature in a later commit
			meta := PackageMeta{}

			// Zero expected checksum, either because we'll error before we
			// reach it, or we want to force a checksum mismatch
			auth := NewArchiveChecksumAuthentication([sha256.Size]byte{0})
			result, err := auth.AuthenticatePackage(meta, test.location)

			if result != nil {
				t.Errorf("wrong result: got %#v, want nil", result)
			}
			if gotErr := err.Error(); gotErr != test.err {
				t.Errorf("wrong err: got %q, want %q", gotErr, test.err)
			}
		})
	}
}

// Matching checksum authentication success takes a SHA256SUMS document, an
// archive filename, and an expected SHA256 hash. On success both return values
// should be nil.
func TestMatchingChecksumAuthentication_success(t *testing.T) {
	// PackageMeta is unused by this authentication mechanism
	// FIXME: and really by all the others, so let's remove it from the call
	// signature in a later commit
	meta := PackageMeta{}

	// Location is unused
	location := PackageLocalArchive("testdata/my-package.zip")

	// Two different checksums for other files
	wantSHA256Sum := [sha256.Size]byte{0xde, 0xca, 0xde}
	otherSHA256Sum := [sha256.Size]byte{0xc0, 0xff, 0xee}

	document := []byte(
		fmt.Sprintf(
			"%x README.txt\n%x my-package.zip\n",
			otherSHA256Sum,
			wantSHA256Sum,
		),
	)
	filename := "my-package.zip"

	auth := NewMatchingChecksumAuthentication(document, filename, wantSHA256Sum)
	result, err := auth.AuthenticatePackage(meta, location)

	if result != nil {
		t.Errorf("wrong result: got %#v, want nil", result)
	}
	if err != nil {
		t.Errorf("wrong err: got %s, want nil", err)
	}
}

// Matching checksum authentication can fail for three reasons: no checksum
// in the document for the filename, invalid checksum value, and non-matching
// checksum value.
func TestMatchingChecksumAuthentication_failure(t *testing.T) {
	wantSHA256Sum := [sha256.Size]byte{0xde, 0xca, 0xde}
	filename := "my-package.zip"

	tests := map[string]struct {
		document []byte
		err      string
	}{
		"no checksum for filename": {
			[]byte(
				fmt.Sprintf(
					"%x README.txt",
					[sha256.Size]byte{0xbe, 0xef},
				),
			),
			`checksum list has no SHA-256 hash for "my-package.zip"`,
		},
		"invalid checksum": {
			[]byte(
				fmt.Sprintf(
					"%s README.txt\n%s my-package.zip",
					"horses",
					"chickens",
				),
			),
			`checksum list has invalid SHA256 hash "chickens": encoding/hex: invalid byte: U+0068 'h'`,
		},
		"checksum mismatch": {
			[]byte(
				fmt.Sprintf(
					"%x README.txt\n%x my-package.zip",
					[sha256.Size]byte{0xbe, 0xef},
					[sha256.Size]byte{0xc0, 0xff, 0xee},
				),
			),
			"checksum list has unexpected SHA-256 hash c0ffee0000000000000000000000000000000000000000000000000000000000 (expected decade0000000000000000000000000000000000000000000000000000000000)",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// PackageMeta is unused by this authentication mechanism
			// FIXME: and really by all the others, so let's remove it from the call
			// signature in a later commit
			meta := PackageMeta{}

			// Location is unused
			location := PackageLocalArchive("testdata/my-package.zip")

			auth := NewMatchingChecksumAuthentication(test.document, filename, wantSHA256Sum)
			result, err := auth.AuthenticatePackage(meta, location)

			if result != nil {
				t.Errorf("wrong result: got %#v, want nil", result)
			}
			if gotErr := err.Error(); gotErr != test.err {
				t.Errorf("wrong err: got %q, want %q", gotErr, test.err)
			}
		})
	}
}
