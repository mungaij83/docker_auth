package app

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"reflect"
	"strconv"
	"strings"
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
	tokenDB  authn.TokenDB
	ldapAuth *authn.LDAPAuth
	config   *utils.Oauth2Config
	auth     *AuthService
}

func NewOauth2(c *utils.Config, authS *AuthService) (*Oauth2Auth, error) {
	if c.Oauth2 == nil {
		return nil, errors.New("configuration is null")
	}
	ldap, err := authn.NewLDAPAuth(c.LDAPAuth)
	if err != nil {
		return nil, err
	}

	db, err := authn.NewTokenDB(c.Oauth2.TokenDb)
	if err != nil {
		return nil, err
	}
	return &Oauth2Auth{tokenDB: db, ldapAuth: ldap, config: c.Oauth2, auth: authS}, nil
}

// Generate OAUTH authorization code for a valida authentication
// The code generate payload is then store in a token db ready for claim
func (a Oauth2Auth) CreateAuthorizationCode(ar *utils.AuthRequest, ares []utils.AuthzResult) (utils.StringMap, error) {
	code, err := a.auth.CreateAuthorizationToken(ar, ares)
	if err != nil {
		return nil, err
	}
	authPayload, signAlg, err := a.auth.GetClaims(ar, ares)
	if err != nil {
		return nil, err
	}
	value := utils.StringMap{}
	value.Add("service", ar.Service)
	value.Add(utils.JwtSubField, ar.Account)
	value.Add(utils.AlgorithmField, signAlg)
	value.Add(utils.PayloadField, authPayload)
	delete(code, utils.AlgorithmField)
	authCode := code.GetString(utils.AuthorizationCodeField)
	err = a.tokenDB.StoreData(authCode, AuthorizationCodeRequestType, value)
	if err != nil {
		return nil, err
	}

	return code, nil
}

func (a Oauth2Auth) GenerateAccessToken(user string, password utils.PasswordString) (bool, utils.StringMap, error) {
	ok, lbls, err := a.ldapAuth.Authenticate(user, password)
	if err != nil {
		return false, nil, err
	}
	labels := utils.StringMap{}
	if ok {

		value := &authn.TokenDBValue{
			TokenType:  ClientCredentialsGrant,
			Labels:     lbls,
			ValidUntil: time.Now().Add(time.Duration(a.config.ExpiryTime) * time.Minute),
		}
		secret, err := a.tokenDB.StoreToken(user, value, true)
		if err != nil {
			return false, nil, err
		}
		glog.V(2).Info("Token: %v", secret)
	}

	return ok, labels, nil
}
func (a Oauth2Auth) ValidateAccount(user string, password utils.PasswordString) (utils.StringMap, error) {
	ok, lbls, err := a.ldapAuth.Authenticate(user, password)
	if err != nil {
		return nil, err
	}
	labels := utils.StringMap{}
	if ok {
		clientSecret := strconv.FormatInt(int64(time.Now().Nanosecond()), 10)
		labels["client_id"] = user
		labels["client_secret"] = clientSecret
		lbls["client_secret"] = []string{clientSecret}
		value := &authn.TokenDBValue{
			TokenType:  ClientCredentialsGrant,
			Labels:     lbls,
			ValidUntil: time.Now().Add(time.Duration(a.config.ExpiryTime) * time.Minute),
		}
		secret, err := a.tokenDB.StoreToken(user, value, true)
		if err != nil {
			return nil, err
		}
		glog.V(2).Info("Token: %v", secret)
	}

	return labels, nil
}
func (a Oauth2Auth) Authenticate(user string, password utils.PasswordString) (bool, utils.Labels, error) {
	return a.ldapAuth.Authenticate(user, password)
}

func (a Oauth2Auth) Stop() {

}

func (a Oauth2Auth) Name() string {
	return "oauth_2"
}

// Validate request type, client_id, and request direction
func (a Oauth2Auth) ValidateClientDetails(client utils.AuthDetails) (bool, error) {
	if strings.Compare(client.ResponseType, "code") != 0 || strings.Compare(client.ResponseType, "token") != 0 {
		return false, errors.New(fmt.Sprintf("Invalid request type: %v", client.ResponseType))
	}
	c, ok := a.config.Clients[client.ClientId]
	if !ok {
		return false, errors.New(fmt.Sprintf("Invalid client id: %v", client.ClientId))
	}
	// TODO: Check remote host
	scopes := strings.Split(client.Scope, ":")
	var err error
	for _, v := range scopes {
		if !itemExists(c.Scopes, v) {
			err = errors.New(fmt.Sprintf("invalid scope: %v", v))
			break
		}
	}
	return true, err
}

// Validate access_token or generate a new access token
func (a Oauth2Auth) ValidateAuthToken(token utils.TokenDetails) (utils.StringMap, error) {

	switch token.RequestType {
	case "validate":
		details, err := a.tokenDB.GetData(token.AccessToken, AccessTokenNamespace)
		if err != nil {
			return nil, err
		}
		sigAlg := details.GetString(utils.AlgorithmField)
		return a.auth.ValidateJWT(token.AccessToken, sigAlg, false)
	case "refresh":
		details, err := a.tokenDB.GetData(token.RefreshToken, RefreshTokenNamespace)
		if err != nil {
			return nil, err
		}
		sigAlg := details.GetString(utils.AlgorithmField)
		return a.auth.ValidateJWT(token.AccessToken, sigAlg, false)
	default:
		return nil, errors.New(fmt.Sprintf("invalid request type: %v", token.RequestType))
	}
}
func (a Oauth2Auth) ValidateResponseCode(client utils.AuthDetails) (utils.StringMap, error) {
	if client.ResponseType != AccessTokenRequestType {
		return nil, errors.New(fmt.Sprintf("Invalid request type: %v", client.ResponseType))
	}
	c, ok := a.config.Clients[client.ClientId]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Invalid client id: %v", client.ClientId))
	}

	if strings.Compare(client.ClientSecret, c.ClientSecret) != 0 {
		return nil, errors.New("invalid client secret")
	}
	data, err := a.tokenDB.GetData(client.AuthorizationCode, AuthorizationCodeRequestType)
	if err != nil {
		return nil, err
	}
	err = a.tokenDB.DeleteTokenNs(client.AuthorizationCode, AuthorizationCodeRequestType)
	if err != nil {
		glog.V(3).Infof("Failed to delete token from store: %+v", err)
	}
	//TODO: validate signature
	glog.V(2).Infof("Token retrieved from db: %+v", data)
	signAlg := data.GetString(utils.AlgorithmField)
	payload := data.GetString(utils.PayloadField)
	// Generate JWT auth with the payload data
	result, err := a.auth.GenerateJWT(payload, signAlg)
	if err != nil {
		return nil, err
	}
	// Access token
	err = a.StoreJwtDetails(result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (a Oauth2Auth) StoreJwtDetails(result utils.StringMap) error {
	accessToken := result.GetString(utils.AccessTokenField)
	err := a.tokenDB.StoreData(accessToken, AccessTokenNamespace, result)
	if err != nil {
		return err
	}
	refreshToken := result.GetString(utils.RefreshTokenField)
	if len(refreshToken) > 0 {
		err = a.tokenDB.StoreData(refreshToken, RefreshTokenNamespace, result)
		if err != nil {
			return err
		}
	}
	return nil
}

// Password grant token generation
// Validate client password before token generation
func (a Oauth2Auth) PasswordGrantToken(request *utils.AuthRequest, results []utils.AuthzResult, client utils.AuthDetails) (utils.StringMap, error) {
	c, ok := a.config.Clients[client.ClientId]
	if !ok {
		glog.Infof("Client not found")
		return nil, fmt.Errorf("invalid client credentials or details: %s", client.ClientId)
	}
	if strings.Compare(c.ClientSecret, client.ClientSecret) != 0 {
		glog.Infof("Invalid client secret: %s", client.ClientSecret)
		return nil, fmt.Errorf("invalid client credentials or details: %s", client.ClientId)
	}
	payload, sigAlg, err := a.auth.GetClaims(request, results)
	if err != nil {
		return nil, err
	}
	// Generate JWT token
	result, err := a.auth.GenerateJWT(payload, sigAlg)
	if err != nil {
		return nil, err
	}
	// Store access token and refresh token
	err = a.StoreJwtDetails(result)
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
