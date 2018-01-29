package token

// Validator can Validate a JWT and return a Claim object
type Validator interface {
	Validate(jwt string) (Claim, error)
}
