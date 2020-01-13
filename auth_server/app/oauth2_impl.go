package app

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"reflect"
	"strconv"
	"time"
)

// Authorization grant types
const (
	ClientCredentialsGrant     = "client_credentials"
	PasswordGrant              = "password"
	ImplicitGrant              = "implicit"
	AuthorizationCodeGrantType = "authorization_code"
)

// Override response type
const (
	PasswordRequestType = "token_password"
)

// OAuth 2 Response type
const (
	AuthorizationCodeRequestType = "code"
	AccessTokenRequestType       = "token"
)

// Namespaces
const (
	AccessTokenNamespace  = "token"
	RefreshTokenNamespace = "refresh"
)

type Oauth2Auth struct {
	config *utils.Oauth2Config
	auth   *AuthService
	jwt    Jwt
}

func NewOauth2(c *utils.Config, authS *AuthService) (*Oauth2Auth, error) {
	if c.Oauth2 == nil {
		return nil, errors.New("configuration is null")
	}

	return &Oauth2Auth{config: c.Oauth2, auth: authS, jwt: Jwt{c.Token}}, nil
}

// Generate OAUTH authorization code for a valida authentication
// The code generate payload is then store in a token db ready for claim
func (a Oauth2Auth) CreateAuthorizationCode(ar *utils.AuthRequest) (utils.StringMap, error) {
	ok, principal, err := a.auth.AuthenticateUser(ar)
	if err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("invalid result")
	}
	code, err := a.auth.CreateAuthorizationToken(ar, principal.Roles)
	if err != nil {
		return nil, err
	}
	authPayload, signAlg, err := a.jwt.GetClaims(*principal, true)
	if err != nil {
		return nil, err
	}
	altPayload, signAlg, err := a.jwt.GetClaims(*principal, false)
	if err != nil {
		return nil, err
	}
	value := utils.StringMap{}
	value.Add("service", ar.Service)
	// Account details
	value.Add(utils.JwtSubField, ar.Account)
	value.Add(utils.AlgorithmField, signAlg)
	value.Add(utils.PayloadField, authPayload)
	value.Add(utils.AltPayloadField, altPayload)
	delete(code, utils.AlgorithmField)
	authCode := code.GetString(utils.AuthorizationCodeField)
	err = a.auth.tokenDB.StoreData(authCode, AuthorizationCodeRequestType, value)
	if err != nil {
		return nil, err
	}

	return code, nil
}

//func (a Oauth2Auth) GenerateAccessToken(user string, lbls utils.Labels) (bool, error) {
//
//	value := &authn.TokenDBValue{
//		TokenType:  ClientCredentialsGrant,
//		Labels:     lbls,
//		ValidUntil: time.Now().Add(time.Duration(a.config.ExpiryTime) * time.Minute),
//	}
//	secret, err := a.tokenDB.StoreToken(user, value, true)
//	if err != nil {
//		return false, nil, err
//	}
//	glog.V(2).Info("Token: %v", secret)
//
//	return true, nil
//}

func (a Oauth2Auth) ValidateAccount(ar *utils.AuthRequest) (*utils.PrincipalDetails, error) {
	ok, principal, err := a.auth.AuthenticateUser(ar)
	if err != nil {
		return nil, err
	}
	labels := utils.StringMap{}
	if ok {
		clientSecret := strconv.FormatInt(int64(time.Now().Nanosecond()), 10)
		labels["client_id"] = ar.User
		labels["client_secret"] = clientSecret
		value := &authn.TokenDBValue{
			TokenType:  ClientCredentialsGrant,
			Labels:     labels,
			ValidUntil: time.Now().Add(time.Duration(a.config.ExpiryTime) * time.Minute),
		}
		secret, err := a.auth.tokenDB.StoreToken(ar.User, value, true)
		if err != nil {
			return nil, err
		}
		glog.V(2).Info("Token: %v", secret)
	}

	return principal, nil
}

func (a Oauth2Auth) Stop() {

}

func (a Oauth2Auth) Name() string {
	return "oauth_2_authorizer"
}

// Validate access_token or generate a new access token
func (a Oauth2Auth) ValidateAuthToken(token utils.TokenDetails) (utils.StringMap, error) {

	switch token.RequestType {
	case "validate":
		details, err := a.auth.tokenDB.GetData(token.AccessToken, AccessTokenNamespace)
		if err != nil {
			return nil, err
		}
		sigAlg := details.GetString(utils.AlgorithmField)
		return a.auth.ValidateJWT(token.AccessToken, sigAlg, false)
	case "refresh":
		details, err := a.auth.tokenDB.GetData(token.RefreshToken, RefreshTokenNamespace)
		if err != nil {
			return nil, err
		}
		sigAlg := details.GetString(utils.AlgorithmField)
		return a.auth.ValidateJWT(token.AccessToken, sigAlg, true)
	default:
		return nil, errors.New(fmt.Sprintf("invalid request type: %v", token.RequestType))
	}
}

func (a Oauth2Auth) ValidateResponseCode(client utils.AuthDetails) (utils.StringMap, error) {
	if client.ResponseType != AccessTokenRequestType {
		return nil, errors.New(fmt.Sprintf("Invalid request type: %v", client.ResponseType))
	}
	ok, err := a.auth.ValidateClientDetails(client)
	if err != nil {
		return nil, err
	}
	// Validation failed
	if !ok {
		return nil, errors.New("invalid client id/secret")
	}
	// Get authorization code
	data, err := a.auth.tokenDB.GetData(client.AuthorizationCode, AuthorizationCodeRequestType)
	if err != nil {
		return nil, err
	}
	// Delete access token
	err = a.auth.tokenDB.DeleteTokenNs(client.AuthorizationCode, AuthorizationCodeRequestType)
	if err != nil {
		glog.V(3).Infof("Failed to delete token from store: %+v", err)
		return nil, errors.New("invalid client id /secret")
	}
	glog.V(2).Infof("Token retrieved from db: %+v", data)
	signAlg := data.GetString(utils.AlgorithmField)
	payload := data.GetString(utils.PayloadField)
	altPayload := data.GetString(utils.AltPayloadField)
	// Generate JWT auth with the payload data
	result, err := a.jwt.GenerateJWT(payload, altPayload, signAlg)
	if err != nil {
		return nil, err
	}
	// Access token
	err = a.auth.StoreJwtDetails(result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Password grant token generation
// Validate client password before token generation
func (a Oauth2Auth) PasswordGrantToken(request *utils.AuthRequest, results []utils.AuthzResult, client utils.AuthDetails) (utils.StringMap, error) {
	res := <-command.DataStore.Clients().GetClientForLogin(client.ClientId, client.ClientSecret, true)
	if res.HasError() {
		glog.V(2).Infof("Client not found: %v", res.Error)
		return nil, res.Error
	}
	// Authorize user
	ok, principal, err := a.auth.AuthenticateUser(request)
	if err != nil || !ok {
		glog.V(2).Infof("user find failed[%v]: %v", ok, err)
		return nil, err
	}
	// Access token payload
	payload, sigAlg, err := a.jwt.GetClaims(*principal, true)
	if err != nil {
		return nil, err
	}
	// Refresh token payload
	altPayload, sigAlg, err := a.jwt.GetClaims(*principal, false)
	if err != nil {
		return nil, err
	}
	// Generate JWT token
	result, err := a.jwt.GenerateJWT(payload, altPayload, sigAlg)
	if err != nil {
		return nil, err
	}
	// Store access token and refresh token
	err = a.auth.StoreJwtDetails(result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func itemExists(arrayType interface{}, item interface{}) bool {
	arr := reflect.ValueOf(arrayType)

	if arr.Kind() != reflect.Slice {
		panic(fmt.Sprintf("Invalid data-type: %v", arr.Kind()))
	}

	for i := 0; i < arr.Len(); i++ {
		if arr.Index(i).Interface() == item {
			return true
		}
	}

	return false
}
