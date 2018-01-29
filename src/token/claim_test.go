package token

import "testing"

func Test_GetClaim(t *testing.T) {
	c := Claim{}
	c.Claims = make(map[string]interface{})
	c.Claims["bool"] = true
	c.Claims["float32"] = float32(123.45)
	c.Claims["float64"] = float64(123.45)
	c.Claims["int"] = int(123)
	c.Claims["int32"] = int32(123)
	c.Claims["int64"] = int64(123)
	c.Claims["string"] = "foobar"

	tests := []string{"bool", "float32", "float64", "int", "int32", "int64", "string", "noValue"}

	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			interfaceVal, err := c.GetClaim(v)
			if err != nil && v != "noValue" {
				t.Fatalf("Unexpected error occurred: %s", err.Error())
			}
			if interfaceVal == nil && v != "noValue" {
				t.Fatalf("Unexpected nil value for %s", v)
			}

			b, err := c.GetClaimBool(v)
			if err != nil && v == "bool" {
				t.Fatalf("Unexpected error occurred: %s", err.Error())
			}
			if v == "bool" && !b {
				t.Fatalf("Unexpected bool value for %s - %v", v, b)
			}

			f32, err := c.GetClaimFloat32(v)
			if err != nil && v == "float32" {
				t.Fatalf("Unexpected error occurred: %s", err.Error())
			}
			if v == "float32" && f32 != float32(123.45) {
				t.Fatalf("Unexpected float32 value for %s - %v", v, f32)
			}

			f64, err := c.GetClaimFloat64(v)
			if err != nil && v == "float64" {
				t.Fatalf("Unexpected error occurred: %s", err.Error())
			}
			if v == "float64" && f64 != float64(123.45) {
				t.Fatalf("Unexpected float64 value for %s - %v", v, f64)
			}

			i, err := c.GetClaimInt(v)
			if err != nil && v == "int" {
				t.Fatalf("Unexpected error occurred: %s", err.Error())
			}
			if v == "int" && i != int(123) {
				t.Fatalf("Unexpected int value for %s - %v", v, i)
			}

			i32, err := c.GetClaimInt32(v)
			if err != nil && v == "int32" {
				t.Fatalf("Unexpected error occurred: %s", err.Error())
			}
			if v == "int32" && i32 != int32(123) {
				t.Fatalf("Unexpected int32 value for %s - %v", v, i32)
			}

			i64, err := c.GetClaimInt64(v)
			if err != nil && v == "int64" {
				t.Fatalf("Unexpected error occurred: %s", err.Error())
			}
			if v == "int64" && i64 != int64(123) {
				t.Fatalf("Unexpected int64 value for %s - %v", v, i64)
			}

			s, err := c.GetClaimString(v)
			if err != nil && v == "string" {
				t.Fatalf("Unexpected error occurred: %s", err.Error())
			}
			if v == "string" && s != "foobar" {
				t.Fatalf("Unexpected string value for %s - %v", v, s)
			}
		})
	}

}
