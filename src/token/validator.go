package token

import "net/http"

// Validator can Validate a JWT and return a Claim object
type Validator interface {
	Validate(jwt string) (Claim, error)
	ValidateRequest(r *http.Request) (Claim, error)
}
