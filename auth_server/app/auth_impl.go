package app

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"net"
	"sort"
	"strings"
)

const (
	StaticUserAuthenticationProtocol = "static_auth"
	GithubAuthenticationProtocol     = "github_oauth2"
	GoogleAuthenticationProtocol     = "google_oauth2"
	OpenIdAuthenticationProtocol     = "openid"
	Oauth2AuthenticationProtocol     = "oauth2"
	BasicAuthenticationProtocol      = "basic_auth"
	BasicAuthenticationLDAPProtocol  = "basic_auth_ldap"
)

type AuthService struct {
	config         *utils.Config
	tokenDB        authn.TokenDB
	authenticators map[string]utils.Authenticator
	authorizers    []utils.Authorizer

	googleAuthEnabled bool
	githubAuthEnabled bool
	jwt               Jwt
}

// Authorization service initialization
func NewAuthService(c *utils.Config) (*AuthService, error) {
	db, err := authn.NewTokenDB(c.Oauth2.TokenDb)
	if err != nil {
		return nil, err
	}
	as := &AuthService{
		config:      c,
		tokenDB:     db,
		jwt:         Jwt{Config: c.Token},
		authorizers: make([]utils.Authorizer, 0),
	}
	// Authorizers
	if c.ACL != nil {
		staticAuthorizer, err := authz.NewACLAuthorizer(c.ACL)
		if err != nil {
			return nil, err
		}
		as.authorizers = append(as.authorizers, staticAuthorizer)
	}
	if c.ACLMongo != nil {
		mongoAuthorizer, err := authz.NewACLMongoAuthorizer(c.ACLMongo)
		if err != nil {
			return nil, err
		}
		as.authorizers = append(as.authorizers, mongoAuthorizer)
	}
	if c.ExtAuthz != nil {
		extAuthorizer := authz.NewExtAuthzAuthorizer(c.ExtAuthz)
		as.authorizers = append(as.authorizers, extAuthorizer)

	}
	// Authenticators
	if c.Users != nil {
		as.authenticators[StaticUserAuthenticationProtocol] = authn.NewStaticUserAuth(c.Users)
		AddProtocol(StaticUserAuthenticationProtocol, "Static users")
	}

	if c.GoogleAuth != nil {
		ga, err := authn.NewGoogleAuth(c.GoogleAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators[GoogleAuthenticationProtocol] = ga
		as.googleAuthEnabled = true
		AddProtocol(GoogleAuthenticationProtocol, "Google Oauth")
	}
	if c.GitHubAuth != nil {
		gha, err := authn.NewGitHubAuth(c.GitHubAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators[GithubAuthenticationProtocol] = gha
		as.githubAuthEnabled = true
		AddProtocol(GithubAuthenticationProtocol, "Github Authentication")
	}
	if c.LDAPAuth != nil {
		la, err := authn.NewLDAPAuth(c.LDAPAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators[BasicAuthenticationLDAPProtocol] = la
	}

	if c.MongoAuth != nil {
		ma, err := authn.NewMongoAuth(c.MongoAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators[BasicAuthenticationProtocol] = ma
	}
	if c.PluginAuthn != nil {
		pluginAuthn, err := authn.NewPluginAuthn(c.PluginAuthn)
		if err != nil {
			return nil, err
		}
		as.authenticators[pluginAuthn.PluginProtocol] = pluginAuthn
		AddProtocol(pluginAuthn.PluginProtocol, pluginAuthn.ProtocolDescription)
	}
	// Add all protocols if not exits
	AddProtocol(OpenIdAuthenticationProtocol, "OpenId connect protocol")
	AddProtocol(BasicAuthenticationProtocol, "Basic Authentication protocol")
	AddProtocol(Oauth2AuthenticationProtocol, "Oauth2 Authentication protocol")
	AddProtocol(BasicAuthenticationLDAPProtocol, "Basic Auth with LDAP")
	return as, nil
}

func AddProtocol(protocolId, description string) {
	var p models.AuthenticationProtocol
	p.Description = description
	p.ProtocolId = protocolId
	res := <-command.DataStore.Settings().AddAuthenticationProtocol(p)
	if res.HasError() {
		glog.Infof("failed to add protocol: %+v", res)
	}
}

// Authenticate user using client selected authentication methods
func (as *AuthService) AuthenticateUser(ar *utils.AuthRequest) (bool, *utils.PrincipalDetails, error) {
	res := <-command.DataStore.Clients().GetClientByClientId(ar.ClientId)
	if res.HasError() {
		return false, nil, res.Error
	}

	client, ok := res.Data.(*models.Clients)
	if !ok {
		glog.Infof("Invalid result model for client data")
		return false, nil, nil
	}
	// Select protocol
	a, ok := as.authenticators[client.ClientProtocol]
	if !ok {
		glog.Infof("Authentication method/scheme not registered: %v", client.ClientProtocol)
		return false, nil, fmt.Errorf("invalid authentication protocol: %v", client.ClientProtocol)
	}
	// Authenticate user using client protocol
	result, labels, err := a.Authenticate(ar.Account, ar.Password, client.AppRealm)
	glog.V(2).Infof("Authn %s %s -> %t, %+v, %v", a.Name(), ar.Account, result, labels, err)
	if err != nil {
		if err == utils.WrongPass {
			glog.Warningf("Failed authentication with %s: %s", err, ar.Account)
			return false, nil, errors.New("invalid username or password")
		}
		err = fmt.Errorf("authn[%s] returned error: %s", client.ClientProtocol, err)
		glog.Errorf("%s: %s", ar, err)
		return false, nil, err
	} else if result {
		return result, labels, nil
	}
	glog.Warningf("%s did not match any authn rule", ar)
	// Deny by default.
	return false, nil, nil
}

// Validate request type, client_id, and request direction
func (as *AuthService) ValidateClientDetails(client utils.AuthDetails) (bool, error) {
	if strings.Compare(client.ResponseType, "code") != 0 || strings.Compare(client.ResponseType, "token") != 0 {
		return false, errors.New(fmt.Sprintf("Invalid request type: %v", client.ResponseType))
	}
	res := <-command.DataStore.Clients().GetClientByClientId(client.ClientId)
	if res.HasError() {
		return false, res.Error
	}
	c, ok := res.Data.(*models.Clients)
	if !ok {
		return false, errors.New(fmt.Sprintf("Invalid client id: %v", client.ClientId))
	}
	// Check grant type allowed on client
	switch client.GrantType {
	case AuthorizationCodeGrantType:
		if !c.StandardFlowEnabled {
			return false, errors.New("client is not allowed to request access code")
		}
		break
	case ImplicitGrant:
		if !c.ImplicitFlowEnabled {
			return false, errors.New("client is not allowed to request access token")
		}
		break
	case PasswordGrant:
		if !c.PasswordGrantEnabled {
			return false, errors.New("client is not allowed to direct grant")
		}
		break
	case ClientCredentialsGrant:
		// Validate hashed password
		h, _ := utils.NewHashParameters(true, "", c.ClientSecret)
		if !h.ValidateHash(client.ClientSecret) {
			glog.Infof("invalid client secret")
			return false, errors.New("invalid client id or secret")
		}
		break
	default:
		return false, fmt.Errorf("invalid grant type %s", client.GrantType)
	}

	// TODO: Check remote host
	//scopes := strings.Split(client.Scope, ":")
	var err error
	//for _, v := range scopes {
	// TODO: check allowed scope
	//if !itemExists(c.Scopes, v) {
	//	err = errors.New(fmt.Sprintf("invalid scope: %v", v))
	//	break
	//}
	//}
	return true, err
}

func (as *AuthService) ParseRequest(req *Context, ipAddr net.IP) (*utils.AuthRequest, error) {
	ar := &utils.AuthRequest{RemoteConnAddr: req.IpAddress, RemoteAddr: req.IpAddress}
	if as.config.Server.RealIPHeader != "" {
		hv := req.HeaderParams.Get(as.config.Server.RealIPHeader)
		ips := strings.Split(hv, ",")

		realIPPos := as.config.Server.RealIPPos
		if realIPPos < 0 {
			realIPPos = len(ips) + realIPPos
			if realIPPos < 0 {
				realIPPos = 0
			}
		}

		ar.RemoteAddr = strings.TrimSpace(ips[realIPPos])
		glog.V(3).Infof("Conn ip %s, %s: %s, addr: %s", ar.RemoteAddr, as.config.Server.RealIPHeader, hv, ar.RemoteAddr)
		if ar.RemoteAddr == "" {
			return nil, fmt.Errorf("client address not provided")
		}
	}
	ar.RemoteIP = ipAddr
	if ar.RemoteIP == nil {
		return nil, fmt.Errorf("unable to parse remote addr %s", ar.RemoteAddr)
	}
	// Authorization data
	scope := ""
	if req.HaveBasicAuth {
		scope = req.GetUrlParam("scope")
		ar.User = req.Data.GetString("username")
		ar.Account = ar.User
		ar.Password = utils.PasswordString(req.Data.GetString("password"))
	} else if req.IsMultipart() {
		scope = req.FormData.Get("scope")
		ar.Service = req.FormData.Get("service")
		ar.Account = req.FormData.Get("account")
		ar.User = req.FormData.Get("account")
	} else {
		scope = req.Data.GetString("scope")
		ar.Service = req.Data.GetString("service")
		// username and password could be part of form data
		username := req.Data.GetString("username")
		password := req.Data.GetString("password")
		if username != "" && password != "" {
			ar.User = username
			ar.Account = username
			ar.Password = utils.PasswordString(password)
		}
	}
	// Parse scope in request
	if scope != "" {
		for _, scopeStr := range req.FormData["scope"] {
			parts := strings.Split(scopeStr, ":")
			var scope utils.AuthScope
			switch len(parts) {
			case 3:
				scope = utils.AuthScope{
					Type:    parts[0],
					Name:    parts[1],
					Actions: strings.Split(parts[2], ","),
				}
			case 4:
				scope = utils.AuthScope{
					Type:    parts[0],
					Name:    parts[1] + ":" + parts[2],
					Actions: strings.Split(parts[3], ","),
				}
			default:
				return nil, fmt.Errorf("invalid scope: %q", scopeStr)
			}
			sort.Strings(scope.Actions)
			ar.Scopes = append(ar.Scopes, scope)
		}
	}
	return ar, nil
}

func (as *AuthService) authorizeScope(ai *utils.AuthRequestInfo) ([]string, error) {

	for i, a := range as.authorizers {
		result, err := a.Authorize(ai)
		glog.V(2).Infof("Authz %s %s -> %s, %s", a.Name(), *ai, result, err)
		if err != nil {
			if err == utils.NoMatch {
				continue
			}
			err = fmt.Errorf("authz #%d returned error: %s", i+1, err)
			glog.Errorf("%s: %s", *ai, err)
			return nil, err
		}
		return result, nil
	}
	// Deny by default.
	glog.Warningf("%s did not match any authz rule", *ai)
	return nil, nil
}

func (as *AuthService) StoreJwtDetails(result utils.StringMap) error {
	accessToken := result.GetString(utils.AccessTokenField)
	err := as.tokenDB.StoreData(accessToken, AccessTokenNamespace, result)
	if err != nil {
		return err
	}
	refreshToken := result.GetString(utils.RefreshTokenField)
	if len(refreshToken) > 0 {
		err = as.tokenDB.StoreData(refreshToken, RefreshTokenNamespace, result)
		if err != nil {
			return err
		}
	}
	return nil
}

func (as *AuthService) Authorize(ar *utils.AuthRequest) ([]utils.AuthzResult, error) {

	ares := make([]utils.AuthzResult, 0)
	for _, scope := range ar.Scopes {
		ai := &utils.AuthRequestInfo{
			Account: ar.Account,
			Type:    scope.Type,
			Name:    scope.Name,
			Service: ar.Service,
			IP:      ar.RemoteIP,
			Actions: scope.Actions,
			Labels:  ar.Labels,
		}
		actions, err := as.authorizeScope(ai)
		if err != nil {
			return nil, err
		}
		ares = append(ares, utils.AuthzResult{Scope: scope, AutorizedActions: actions})
	}
	return ares, nil
}

// https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md#example
func (as *AuthService) CreateToken(pricipal utils.PrincipalDetails) (utils.StringMap, error) {
	payload, sigAlg, err := as.jwt.GetClaims(pricipal, true)
	if err != nil {
		return nil, err
	}
	return as.jwt.GenerateJWT(payload, "", sigAlg)
}

// Validates a JWT token
func (as *AuthService) ValidateJWT(tokenStr, signAlg string, isAlt bool) (utils.StringMap, error) {
	claims, err := as.jwt.ValidateJWT(tokenStr, signAlg, isAlt)
	if err != nil {
		return nil, err
	}
	return utils.ToStringMap(claims), nil
}

// Creates authorization token
func (as *AuthService) CreateAuthorizationToken(ar *utils.AuthRequest, ares []utils.AuthzResult) (utils.StringMap, error) {
	payload, err := utils.RandomString(15, false)
	tc := &as.config.Token
	_, sigAlg, err := tc.GetPrivateKey().Sign(strings.NewReader("dummy"), 0)
	if err != nil {
		return nil, err
	}
	tokenResult := utils.StringMap{}

	sig, sigAlg2, err := tc.GetPrivateKey().Sign(strings.NewReader(payload), 0)
	if err != nil || sigAlg2 != sigAlg {
		return tokenResult, fmt.Errorf("failed to sign token: %s", err)
	}

	tokenResult.Add(utils.JwtSubField, ar.Account)
	tokenResult.Add(utils.AlgorithmField, sigAlg)
	tokenResult.Add("service", ar.Service)
	tokenResult.Add(utils.AuthorizationCodeField, utils.JsonBase64UrlEncode(sig))
	return tokenResult, nil
}

// https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md#example
// Generate access token and refresh token
func (as *AuthService) CreateOAuthToken(principal utils.PrincipalDetails) (utils.StringMap, error) {
	payload, sigAlg, err := as.jwt.GetClaims(principal, true)
	if err != nil {
		return nil, err
	}

	refreshPayload, _, err := as.jwt.GetClaims(principal, false)
	if err != nil {
		return nil, err
	}
	glog.Infof("New token for  %+v", principal)
	return as.jwt.GenerateJWT(payload, refreshPayload, sigAlg)
}

func (as *AuthService) GetToken() utils.TokenConfig {
	return as.config.Token
}

func (as *AuthService) GetServerConfig() utils.ServerConfig {
	return as.config.Server
}

func (as *AuthService) GoogleAuthEnabled() bool {
	return as.googleAuthEnabled
}

func (as *AuthService) GithubAuthEnabled() bool {
	return as.githubAuthEnabled
}

func (as *AuthService) Stop() {
	for _, an := range as.authenticators {
		an.Stop()
	}
	for _, az := range as.authorizers {
		az.Stop()
	}
	glog.Infof("Server stopped")
}

// Client credentials grant type
func (as *AuthService) GrantClientCredentials(client utils.AuthDetails, principal utils.PrincipalDetails) (utils.StringMap, error) {
	res := <-command.DataStore.Clients().GetClientByClientId(client.ClientId)
	if res.HasError() {
		glog.Infof("client not found: %+v", res)
		return nil, res.Error
	}

	c, ok := res.Data.(*models.Clients)
	if !ok {
		glog.Infof("Invalid client id: %v", client.ClientId)
		return nil, errors.New("invalid client id or secret")
	}
	// Dont allow public client to authenticate
	switch c.ClientType {
	case models.PublicClient:
		glog.V(2).Infof("client [%s] is a public client. Auth denied", c.ClientId)
		return nil, errors.New("invalid client id or secret")
	case models.ConfidentialClient:
		glog.V(2).Infof("client [%s] is a confidential client. Auth proceed", c.ClientId)
		break
	default:
		return nil, fmt.Errorf("client type [%s] unrecognized ", c.ClientType)
	}
	// Validate hashed password
	h, _ := utils.NewHashParameters(true, "", c.ClientSecret)
	if !h.ValidateHash(client.ClientSecret) {
		glog.Infof("invalid client secret")
		return nil, errors.New("invalid client id or secret")
	}
	payload, sigAlg, err := as.jwt.GetClaims(principal, true)
	if err != nil {
		return nil, err
	}
	glog.V(2).Infof("Grant client credentials")
	return as.jwt.GenerateJWT(payload, "", sigAlg)
}
