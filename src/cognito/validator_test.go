package cognito

import (
	"testing"
)

func Test_DownloadCerts(t *testing.T) {
	//https://cognito-idp.us-east-1.amazonaws.com/us-east-1_gENunu2aW/.well-known/jwks.json
	type test struct {
		name          string
		region        string
		userPoolID    string
		keyCount      int
		expectedError bool
	}
	tests := []test{
		{
			name:       "base path",
			region:     "us-east-1",
			userPoolID: "us-east-1_gENunu2aW", // this test user pool may not exist in the future
			keyCount:   2,
		},
		{
			name:          "exceptional path",
			region:        "us-east-1",
			userPoolID:    "foobar",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := downloadCerts(tc.region, tc.userPoolID)
			if err != nil && !tc.expectedError {
				t.Fatalf("Unexpected error occurred: %v", err)
			}
			if len(keys) != tc.keyCount {
				t.Fatalf("Expected %d keys, got %d", tc.keyCount, len(keys))
			}
		})
	}
}
