package token

import (
	"fmt"
)

// Claim holds all the claim information from a JWT and provides helpers to access them
type Claim struct {
	ID     string
	Role   string
	Claims map[string]interface{}
}

// GetUserID will return the user's id
func (c Claim) GetUserID() string {
	return c.ID
}

// IsUser returns true if this claim is for the provided user
func (c Claim) IsUser(userID string) bool {
	return c.ID == userID
}

// GetRole will return the user's role
func (c Claim) GetRole() string {
	return c.Role
}

// IsRole returns true if this claim is for the provided role
func (c Claim) IsRole(role string) bool {
	return c.Role == role
}

// GetClaim returns the claim as an interface or an error if it does not exist
func (c Claim) GetClaim(key string) (interface{}, error) {
	if v, ok := c.Claims[key]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("claim %s does not exist", key)
}

// GetClaimString returns the claim as a string if possible
func (c Claim) GetClaimString(key string) (string, error) {
	v, err := c.GetClaim(key)
	if err != nil {
		return "", err
	}
	if v != nil {
		if ret, ok := v.(string); ok {
			return ret, nil
		}
	}
	return "", fmt.Errorf("claim %s is not a string", key)
}

// GetClaimBool returns the claim as a bool if possible
func (c Claim) GetClaimBool(key string) (bool, error) {
	v, err := c.GetClaim(key)
	if err != nil {
		return false, err
	}
	if v != nil {
		if ret, ok := v.(bool); ok {
			return ret, nil
		}
	}
	return false, fmt.Errorf("claim %s is not a bool", key)
}

// GetClaimInt64 returns the claim as a int64 if possible
func (c *Claim) GetClaimInt64(key string) (int64, error) {
	v, err := c.GetClaim(key)
	if err != nil {
		return 0, err
	}
	if v != nil {
		if ret, ok := v.(int64); ok {
			return ret, nil
		}
	}
	return 0, fmt.Errorf("claim %s is not a int64", key)
}

// GetClaimInt32 returns the claim as a int32 if possible
func (c Claim) GetClaimInt32(key string) (int32, error) {
	v, err := c.GetClaim(key)
	if err != nil {
		return 0, err
	}
	if v != nil {
		if ret, ok := v.(int32); ok {
			return ret, nil
		}
	}
	return 0, fmt.Errorf("claim %s is not a int32", key)
}

// GetClaimInt returns the claim as a int if possible
func (c Claim) GetClaimInt(key string) (int, error) {
	v, err := c.GetClaim(key)
	if err != nil {
		return 0, err
	}
	if v != nil {
		if ret, ok := v.(int); ok {
			return ret, nil
		}
	}
	return 0, fmt.Errorf("claim %s is not a int", key)
}

// GetClaimFloat64 returns the claim as a Float64 if possible
func (c Claim) GetClaimFloat64(key string) (float64, error) {
	v, err := c.GetClaim(key)
	if err != nil {
		return 0, err
	}
	if v != nil {
		if ret, ok := v.(float64); ok {
			return ret, nil
		}
	}
	return 0, fmt.Errorf("claim %s is not a float64", key)
}

// GetClaimFloat32 returns the claim as a float32 if possible
func (c Claim) GetClaimFloat32(key string) (float32, error) {
	v, err := c.GetClaim(key)
	if err != nil {
		return 0, err
	}
	if v != nil {
		if ret, ok := v.(float32); ok {
			return ret, nil
		}
	}
	return 0, fmt.Errorf("claim %s is not a float32", key)
}
