package cognito

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func Test_Validate(t *testing.T) {
	// rsa keys are copied from jwt package tests since I know they work there and this test isn't designed to test that package.
	pubKeyData, err := ioutil.ReadFile("../test/sample-key.pub")
	if err != nil {
		t.Fatalf("error reading public key: %s", err.Error())
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyData)
	if err != nil {
		t.Fatalf("Error parsing public key: %s", err.Error())
	}

	privateKeyData, err := ioutil.ReadFile("../test/sample-key")
	if err != nil {
		t.Fatalf("error reading private key: %s", err.Error())
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		t.Fatalf("Error parsing private key: %s", err.Error())
	}

	token := jwt.New(jwt.SigningMethodRS512)
	token.Claims = make(map[string]interface{})
	token.Claims["sub"] = "userid"
	token.Claims["iss"] = "https://cognito-idp.us-east-1.amazonaws.com/test-pool"
	token.Claims["exp"] = fmt.Sprintf("%d", time.Now().Add(5*time.Minute).Unix())
	token.Claims["bool"] = true
	token.Header["kid"] = "testKey"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Could not sign token: %s", err.Error())
	}

	keys := map[string]awsRSAKey{"testKey": awsRSAKey{KID: "testKey", Pub: publicKey}}

	v := NewRS256ValidatorFromKeys([]string{"test-pool"}, "us-east-1", keys)

	c, err := v.Validate(tokenString)
	if err != nil {
		t.Fatalf("Unexpected error validating string: %s", err.Error())
	}

	if c.GetUserID() != "userid" {
		t.Fatalf("Unexpected userID: %v", c.GetUserID())
	}
	if c.GetRole() != "test-pool" {
		t.Fatalf("Unexpected userID: %v", c.GetRole())
	}
	b, err := c.GetClaimBool("bool")
	if !b || err != nil {
		t.Fatalf("Unexpected bool: %v | %s", b, err.Error())
	}
}

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
