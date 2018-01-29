package cognito

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/divideandconquer/go-cognito/src/token"
)

const (
	cognitoIssuer = "https://cognito-idp.%s.amazonaws.com/"
	certURL       = "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"
)

type validator struct {
	keys             map[string]awsRSAKey
	region           string
	issuer           string
	validUserPoolIDs []string
}

type awsRSAKey struct {
	ALG string         `json:"alg"`
	E   string         `json:"e"`
	KID string         `json:"kid"`
	KTY string         `json:"kty"`
	N   string         `json:"n"`
	Use string         `json:"use"`
	Pub *rsa.PublicKey `json:"-"`
}

// NewRS256Validator returns a token.Validator that is specifically designed for Cognito generated JWTs
func NewRS256Validator(validUserPoolIDs []string, awsRegion string) (token.Validator, error) {
	result := validator{region: awsRegion, issuer: fmt.Sprintf(cognitoIssuer, awsRegion), validUserPoolIDs: validUserPoolIDs}
	result.keys = make(map[string]awsRSAKey)

	var allKeys []awsRSAKey
	for _, v := range result.validUserPoolIDs {
		keys, err := downloadCerts(awsRegion, v)
		if err != nil {
			return nil, fmt.Errorf("Could not download signing keys from AWS: %s", err.Error())
		}
		allKeys = append(allKeys, keys...)
	}

	for _, v := range allKeys {
		result.keys[v.KID] = v
	}

	return &result, nil
}

func downloadCerts(region string, userPoolID string) ([]awsRSAKey, error) {
	url := fmt.Sprintf(certURL, region, userPoolID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Could not download RSA cert info: %s", err.Error())
	}
	defer func() {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Could not download RSA cert info.  Status code %d", resp.StatusCode)
	}

	var keys []awsRSAKey
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&keys)
	if err != nil {
		return nil, fmt.Errorf("Could not parse RSA cert into: %s", err.Error())
	}

	for k, v := range keys {
		v.Pub, err = parseRSAPublicKey(v.N, v.E)
		if err != nil {
			return nil, err
		}
		keys[k] = v
	}

	return keys, nil
}

// converts base64 encoded N and E strings into a rsa.PublicKey
func parseRSAPublicKey(nStr string, eStr string) (*rsa.PublicKey, error) {
	decN, err := base64.StdEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("Error decoding N string from public key: %s", err.Error())
	}
	n := big.NewInt(0)
	n.SetBytes(decN)

	decE, err := base64.StdEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("Error decoding E string from public key: %s", err.Error())
	}
	var eBytes []byte
	if len(decE) < 8 {
		eBytes = make([]byte, 8-len(decE), 8)
		eBytes = append(eBytes, decE...)
	} else {
		eBytes = decE
	}
	eReader := bytes.NewReader(eBytes)
	var e uint64
	err = binary.Read(eReader, binary.BigEndian, &e)
	if err != nil {
		return nil, fmt.Errorf("Error reading E as int: %s", err.Error())
	}
	pKey := rsa.PublicKey{N: n, E: int(e)}
	return &pKey, nil
}

func (v *validator) Validate(tokenString string) (token.Claim, error) {
	result := token.Claim{}
	t, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		// validate the alg is what is RSA
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}
		// Get the matching key
		if keyID, ok := t.Header["kid"]; ok {
			if keyIDStr, ok := keyID.(string); ok {
				if signingKey, ok := v.keys[keyIDStr]; ok {
					return signingKey.Pub, nil
				}
			}
		}

		return nil, fmt.Errorf("Could not find matching key for kid %s", t.Header["kid"])
	})
	if err != nil {
		return result, err
	}

	// make sure the token is valid
	if !t.Valid {
		return result, fmt.Errorf("Token not valid")
	}

	// check user id
	var userID string
	if sub, ok := t.Claims["sub"]; ok {
		if subStr, ok := sub.(string); ok {
			userID = subStr
		} else {
			return result, fmt.Errorf("Token sub not properly formatted")
		}
	} else {
		return result, fmt.Errorf("Token is missing the 'sub' claim")
	}

	// check iss and parse role (user pool id)
	var role string
	if iss, ok := t.Claims["iss"]; ok {
		if issStr, ok := iss.(string); ok {
			if !strings.HasPrefix(issStr, v.issuer) {
				return result, fmt.Errorf("Token issuer [%s] does not match expected cognito-idp url [%s]", issStr, v.issuer)
			}
			role = strings.Replace(issStr, v.issuer, "", -1)
		} else {
			return result, fmt.Errorf("Token issuer not properly formatted")
		}
	} else {
		return result, fmt.Errorf("Token is missing the 'iss' claim")
	}

	// make sure the role is a valid user pool id
	roleValid := false
	for _, upID := range v.validUserPoolIDs {
		if upID == role {
			roleValid = true
			break
		}
	}
	if !roleValid {
		return result, fmt.Errorf("Token role [%s] is not valid", role)
	}

	// check expiration if set
	if exp, ok := t.Claims["exp"]; ok {
		if expStr, ok := exp.(string); ok {
			expInt, err := strconv.ParseInt(expStr, 10, 64)
			if err != nil {
				return result, fmt.Errorf("Token expiration not properly formatted")
			}
			if expInt < time.Now().UTC().Unix() {
				return result, fmt.Errorf("Token expired")
			}
		} else {
			return result, fmt.Errorf("Token expiration not properly formatted")
		}
	}

	result.ID = userID
	result.Role = role
	result.Claims = t.Claims
	return result, nil
}
