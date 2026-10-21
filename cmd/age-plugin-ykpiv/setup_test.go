package main

import "testing"

func TestValidateSecret(t *testing.T) {
	bad := []string{"", "12345", "123456789", "123456", "12345678", "000000", "aaaaaaa", "234567", "876543", "12 456", "1234\x00x"}
	for _, s := range bad {
		if validateSecret("PIN", s) == nil {
			t.Errorf("%q accepted", s)
		}
	}
	good := []string{"271828", "k3!vQz9", "90210x77"}
	for _, s := range good {
		if err := validateSecret("PIN", s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
}
