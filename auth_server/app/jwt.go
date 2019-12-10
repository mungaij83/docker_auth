package app

import (
	"encoding/base64"
	"strings"
)

const (
	// TokenSeparator is the value which separates the header, claims, and
	// signature in the compact serialization of a JSON Web Token.
	TokenSeparator = "."
)

type JwtResourceAccess struct {
	Type    string   `json:"type"`
	Class   string   `json:"class,omitempty"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}
type JwtClaims struct {
	// Public claims
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	Expiration int64  `json:"exp"`
	NotBefore  int64  `json:"nbf"`
	IssuedAt   int64  `json:"iat"`
	JWTID      string `json:"jti"`
	// Private claims
	Access []*JwtResourceAccess `json:"access"`
}

type JwtHeader struct {
	Type       string   `json:"typ"`
	SigningAlg string   `json:"alg"`
	KeyID      string   `json:"kid,omitempty"`
	X5c        []string `json:"x5c,omitempty"`
}

type Jwt struct {
}

// Encode JWT specific base64url encoding with padding stripped
func (Jwt) EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func (Jwt) DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
