package getproviders

import "testing"

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
