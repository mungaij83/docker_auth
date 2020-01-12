package utils

import (
	"fmt"
	"testing"
)

func TestValidate(t *testing.T) {
	hsh, err := NewHashParameters(false, Pbkdf2Sha256,"")
	if err != nil {
		t.Errorf("failed: %v", err)
		t.Failed()
		return
	}
	hsh.RawPassword = "test"
	hsh.Cost = 100
	hsh.SaltLength = 32
	hsh.KeyLength = 32

	hashStr := hsh.Encode()
	fmt.Printf("Hashed password: %v\n", hashStr)
}

func TestParseHash(t *testing.T) {
	unixMcf := "$5$9ks3nNEqv31FX.F$gdEoLFsCRsn/WRN3wxUnzfeZLoooVlzeF4WjLomTRFD"
	hsh, err := NewHashParameters(true, "","")
	if err != nil {
		fmt.Printf("failed to init: %v", err)
		t.Failed()
		return
	}
	err = hsh.ParseHash(unixMcf)
	if err != nil {
		fmt.Printf("failed to decode hash: %v", err)
		t.Failed()
		return
	}
	fmt.Printf("hash values: %v", ToJsonPretty(hsh))
	sample := "$PBKDF2_SHA256$100$J9SlFh_kZXXkzQBkAzhWqRM98MDoGrtpdlJNCKyeh90=$UpDWUHoezCpMvUPHr1PkxYHLBIos4o682rzlju2vOSU=$"
	err = hsh.ParseHash(sample)
	if err != nil {
		fmt.Printf("hash is invalid: %v", err)
		t.Failed()
		return
	}
	fmt.Printf("hash2 values: %v", ToJsonPretty(hsh))
}

func TestValidateHash(t *testing.T) {
	sample := "$PBKDF2_SHA256$100$Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk$DngavmnIJAj_Vdx56YQU_bLkEpWroOOy0aXRJZ9SFQo$"
	hsh, err := NewHashParameters(true, "", sample)
	if err != nil {
		fmt.Printf("failed to init: %v", err)
		t.Failed()
		return
	}
	originalPassword := "test"

	fmt.Printf("Hash values: %v", ToJsonPretty(hsh))
	if !hsh.ValidateHash(originalPassword) {
		fmt.Printf("Hash validation failed")
		t.Failed()
	}

}
