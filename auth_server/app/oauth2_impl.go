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

// Authorization modes
const (
	ClientCredentialsGrant = "client_credentials"
	PasswordGrant          = "password"
	ImplicitGrant          = "implicit"
	AuthorizationCode      = "code"
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

// Generate OAUTH authotization code for a valida authentication
// The code generate payload is then store in a token db ready for claim
func (a Oauth2Auth) CreateAuthorizationCode(ar *utils.AuthRequest, ares []utils.AuthzResult) (utils.StringMap, error) {
	code, err := a.auth.CreateAuthorizationToken(ar, ares)
	if err != nil {
		return nil, err
	}
	authPayload, _, err := a.auth.GetClaims(ar, ares)
	if err != nil {
		return nil, err
	}
	value := utils.StringMap{}
	value.Add("service", ar.Service)
	value.Add("sub", ar.Account)
	value.Add("algorithm", code.GetString("algorithm"))
	value.Add("payload", authPayload)
	delete(code, "algorithm")
	authCode := code.GetString(utils.AuthorizationCodeField)
	err = a.tokenDB.StoreData(authCode, AuthorizationCode, value)
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
	if client.ResponseType != "code" {
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
	if client.ResponseType != AccessTokenNamespace {
		return nil, errors.New(fmt.Sprintf("Invalid request type: %v", client.ResponseType))
	}
	c, ok := a.config.Clients[client.ClientId]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Invalid client id: %v", client.ClientId))
	}

	if client.ClientSecret != c.ClientSecret {
		return nil, errors.New("invalid client secret")
	}
	data, err := a.tokenDB.GetData(client.AuthorizationCode, AuthorizationCode)
	if err != nil {
		return nil, err
	}
	err = a.tokenDB.DeleteTokenNs(client.AuthorizationCode, AuthorizationCode)
	if err != nil {
		glog.V(3).Infof("Failed to delete token from store: %+v", err)
	}
	//TODO: validate signature
	glog.V(2).Infof("Token retrieved from db: %+v", data)
	signAlg := data.GetString("algorithm")
	payload := data.GetString("payload")
	// Generate JWT auth with the payload data
	result, err := a.auth.GenerateJWT(payload, signAlg)
	if err != nil {
		return nil, err
	}
	accessToken := result.GetString(utils.AccessTokenField)
	err = a.tokenDB.StoreData(accessToken, AccessTokenNamespace, result)
	if err != nil {
		return nil, err
	}
	refreshToken := result.GetString(utils.RefreshTokenField)
	if len(refreshToken) > 0 {
		err = a.tokenDB.StoreData(refreshToken, RefreshTokenNamespace, result)
		if err != nil {
			return nil, err
		}
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
