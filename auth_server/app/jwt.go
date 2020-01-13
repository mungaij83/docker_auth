package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"math/rand"
	"sort"
	"strings"
	"time"
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
	Config utils.TokenConfig
}

// Generate JWT token with Token and Refresh token
// Refresh token is generated only if refreshPayload is not empty
// And Alt RSA keys are configured
func (jwt Jwt) GenerateJWT(payload string, refreshPayload string, sigAlg string) (utils.StringMap, error) {
	tokenResult := utils.StringMap{}
	var err error
	// Public key configured
	if jwt.Config.GetPublicKey() == nil {
		err = errors.New("public key not configured")
		return tokenResult, err
	}
	// Private key check
	if jwt.Config.GetPrivateKey() == nil {
		err = errors.New("private key not configured")
		return tokenResult, err
	}
	// Token check
	sig, _, err := jwt.Config.GetPrivateKey().Sign(strings.NewReader(payload), 0)
	if err != nil {
		return tokenResult, fmt.Errorf("failed to sign token: %s", err.Error())
	}
	// Generate refresh token
	if jwt.Config.GetAltPrivateKey() != nil {
		sigRefresh, _, err2 := jwt.Config.GetAltPrivateKey().Sign(strings.NewReader(refreshPayload), 0)
		if err2 != nil {
			return tokenResult, fmt.Errorf("failed to sign refresh token: %s", err2.Error())
		}
		// Add access token and refresh token
		tokenResult.Add("refresh_token", fmt.Sprintf("%s%s%s", refreshPayload, TokenSeparator, jwt.EncodeSegment(sigRefresh)))
	}
	// Encode access token and configure expiration time
	tokenResult.Add(utils.AccessTokenField, fmt.Sprintf("%s%s%s", payload, TokenSeparator, jwt.EncodeSegment(sig)))
	glog.Infof("Token: %s", utils.ToJson(tokenResult))
	tokenResult.Add(utils.JwtExpireInField, jwt.Config.Expiration)
	tokenResult.Add(utils.JwtTokenType, "Bearer")
	glog.V(2).Infof("generated JWT token")
	return tokenResult, nil
}

func (jwt Jwt) GetClaims(acc utils.PrincipalDetails, isToken bool) (string, string, error) {
	now := time.Now().Unix()
	// Sign something dummy to find out which algorithm is used.
	_, sigAlg, err := jwt.Config.GetPrivateKey().Sign(strings.NewReader("dummy"), 0)
	if err != nil {
		return "", sigAlg, err
	}
	header := JwtHeader{
		Type:       "JWT",
		SigningAlg: sigAlg,
		KeyID:      jwt.Config.GetPublicKey().KeyID(),
	}
	headerJSON := utils.ToJson(header)

	claims := JwtClaims{
		Issuer:    jwt.Config.Issuer,
		Subject:   acc.Username,
		Audience:  acc.RealmName,
		NotBefore: now - 10,
		IssuedAt:  now,
		JWTID:     fmt.Sprintf("%d", rand.Int63()),
		Access:    []*JwtResourceAccess{},
	}
	// Set token expiration time
	if isToken {
		claims.Expiration = now + jwt.Config.Expiration
	} else {
		claims.Expiration = now + jwt.Config.Expiration + jwt.Config.AltExpiration
	}
	for _, a := range acc.Roles {
		ra := &JwtResourceAccess{
			Type:    a.Scope.Type,
			Class:   a.Scope.ScopeClass,
			Name:    a.Scope.Name,
			Actions: a.Scope.Actions,
		}
		if ra.Actions == nil {
			ra.Actions = []string{}
		}
		sort.Strings(ra.Actions)
		claims.Access = append(claims.Access, ra)
	}
	claimsJSON := utils.ToJson(claims)

	payload := fmt.Sprintf("%s%s%s", jwt.EncodeSegment([]byte(headerJSON)), TokenSeparator, jwt.EncodeSegment([]byte(claimsJSON)))
	return payload, sigAlg, nil
}

// Validate a JWT token
// Decode JWT token header, body then check
// 1. Expiration
// 2. Issuer name
// 3. Signature
func (jwt Jwt) ValidateJWT(tokenStr, signAlg string, isAlt bool) (*JwtClaims, error) {
	parts := strings.Split(tokenStr, TokenSeparator)
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT token")
	}

	// Access token header
	headerJson, err := jwt.DecodeSegment(parts[0])
	if err != nil {
		glog.V(2).Infof("Invalid header encoding: %v", err)
		return nil, err
	}
	var header JwtHeader
	err = utils.FromJson(string(headerJson), &header)
	if err != nil {
		return nil, err
	}
	// Refresh token header
	claimJSON, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		glog.V(2).Infof("Invalid body encoding: %v", err)
		return nil, err
	}
	var claims JwtClaims
	err = utils.FromJson(string(claimJSON), &claims)
	if err != nil {
		return nil, err
	}
	// Validate refresh or access token signature
	signature := parts[2]
	payload := fmt.Sprintf("%s%s%s", parts[0], TokenSeparator, parts[1])
	ds, _ := jwt.DecodeSegment(signature)
	if isAlt {
		if jwt.Config.GetAltPublicKey() != nil {
			return nil, errors.New("invalid refresh token key")
		}
		err = jwt.Config.GetAltPublicKey().Verify(strings.NewReader(payload), header.SigningAlg, ds)
		if err != nil {
			m := "invalid signature"
			glog.V(2).Infof("%s:%v", m, err)
			return nil, errors.New(m)
		}
	} else {
		err = jwt.Config.GetPublicKey().Verify(strings.NewReader(payload), header.SigningAlg, ds)
		if err != nil {
			m := "invalid signature"
			glog.V(2).Infof("%s:%v", m, err)
			return nil, errors.New(m)
		}
	}
	return &claims, nil
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
