package token

import "net/http"

type mockValidator struct {
	claim Claim
	err   error
}

// NewMockValidator will return a validator that will return the provided claim and error
func NewMockValidator(c Claim, err error) Validator {
	return &mockValidator{claim: c, err: err}
}

func (m *mockValidator) Validate(jwt string) (Claim, error) {
	return m.claim, m.err
}

func (m *mockValidator) ValidateRequest(r *http.Request) (Claim, error) {
	return m.claim, m.err
}
