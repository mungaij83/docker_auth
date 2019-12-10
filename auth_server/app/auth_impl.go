package app

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

type AuthService struct {
	config         *utils.Config
	authenticators []utils.Authenticator
	authorizers    []utils.Authorizer
	ga             *authn.GoogleAuth
	gha            *authn.GitHubAuth
	jwt            Jwt
}

// Authorization service initialization
func NewAuthService(c *utils.Config) (*AuthService, error) {
	as := &AuthService{
		config:      c,
		jwt:         Jwt{},
		authorizers: make([]utils.Authorizer, 0),
	}
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
	if c.Users != nil {
		as.authenticators = append(as.authenticators, authn.NewStaticUserAuth(c.Users))
	}
	if c.ExtAuth != nil {
		as.authenticators = append(as.authenticators, authn.NewExtAuth(c.ExtAuth))
	}
	if c.GoogleAuth != nil {
		ga, err := authn.NewGoogleAuth(c.GoogleAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, ga)
		as.ga = ga
	}
	if c.GitHubAuth != nil {
		gha, err := authn.NewGitHubAuth(c.GitHubAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, gha)
		as.gha = gha
	}
	if c.LDAPAuth != nil {
		la, err := authn.NewLDAPAuth(c.LDAPAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, la)
	}
	if c.MongoAuth != nil {
		ma, err := authn.NewMongoAuth(c.MongoAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, ma)
	}
	if c.PluginAuthn != nil {
		pluginAuthn, err := authn.NewPluginAuthn(c.PluginAuthn)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, pluginAuthn)
	}
	if c.PluginAuthz != nil {
		pluginAuthz, err := authz.NewPluginAuthzAuthorizer(c.PluginAuthz)
		if err != nil {
			return nil, err
		}
		as.authorizers = append(as.authorizers, pluginAuthz)
	}
	return as, nil
}

func (as *AuthService) Authenticate(ar *utils.AuthRequest) (bool, utils.Labels, error) {
	for i, a := range as.authenticators {
		result, labels, err := a.Authenticate(ar.Account, ar.Password)
		glog.V(2).Infof("Authn %s %s -> %t, %+v, %v", a.Name(), ar.Account, result, labels, err)
		if err != nil {
			if err == utils.NoMatch {
				continue
			} else if err == utils.WrongPass {
				glog.Warningf("Failed authentication with %s: %s", err, ar.Account)
				return false, nil, nil
			}
			err = fmt.Errorf("authn #%d returned error: %s", i+1, err)
			glog.Errorf("%s: %s", ar, err)
			return false, nil, err
		}
		return result, labels, nil
	}
	// Deny by default.
	glog.Warningf("%s did not match any authn rule", ar)
	return false, nil, nil
}

func (as *AuthService) ParseRequest(req *http.Request, ipAddr net.IP) (*utils.AuthRequest, error) {
	ar := &utils.AuthRequest{RemoteConnAddr: req.RemoteAddr, RemoteAddr: req.RemoteAddr}
	if as.config.Server.RealIPHeader != "" {
		hv := req.Header.Get(as.config.Server.RealIPHeader)
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
	user, password, haveBasicAuth := req.BasicAuth()
	if haveBasicAuth {
		ar.User = user
		ar.Password = utils.PasswordString(password)
	} else if req.Method == "POST" {
		// username and password could be part of form data
		username := req.FormValue("username")
		password := req.FormValue("password")
		if username != "" && password != "" {
			ar.User = username
			ar.Password = utils.PasswordString(password)
		}
	}
	ar.Account = req.FormValue("account")
	if ar.Account == "" {
		ar.Account = ar.User
	} else if haveBasicAuth && ar.Account != ar.User {
		return nil, fmt.Errorf("user and account are not the same (%q vs %q)", ar.User, ar.Account)
	}
	ar.Service = req.FormValue("service")
	if err := req.ParseForm(); err != nil {
		return nil, fmt.Errorf("invalid form value")
	}
	// https://github.com/docker/distribution/blob/1b9ab303a477ded9bdd3fc97e9119fa8f9e58fca/docs/spec/auth/scope.md#resource-scope-grammar
	if req.FormValue("scope") != "" {
		for _, scopeStr := range req.Form["scope"] {
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
func (as *AuthService) CreateToken(ar *utils.AuthRequest, ares []utils.AuthzResult) (string, error) {
	payload, sigAlg, err := as.GetClaims(ar, ares)
	if err != nil {
		return "", err
	}
	tc := &as.config.Token

	sig, sigAlg2, err := tc.GetPrivateKey().Sign(strings.NewReader(payload), 0)
	if err != nil || sigAlg2 != sigAlg {
		return "", fmt.Errorf("failed to sign token: %s", err)
	}
	glog.Infof("New token for %s %+v", *ar, ar.Labels)
	return fmt.Sprintf("%s%s%s", payload, TokenSeparator, utils.JsonBase64UrlEncode(sig)), nil
}

func (as *AuthService) GetClaims(ar *utils.AuthRequest, ares []utils.AuthzResult) (string, string, error) {
	now := time.Now().Unix()
	tc := &as.config.Token
	// Sign something dummy to find out which algorithm is used.
	_, sigAlg, err := tc.GetPrivateKey().Sign(strings.NewReader("dummy"), 0)
	if err != nil {
		return "", sigAlg, err
	}
	header := JwtHeader{
		Type:       "JWT",
		SigningAlg: sigAlg,
		KeyID:      tc.GetPublicKey().KeyID(),
	}
	headerJSON := utils.ToJson(header)

	claims := JwtClaims{
		Issuer:     tc.Issuer,
		Subject:    ar.Account,
		Audience:   ar.Service,
		NotBefore:  now - 10,
		IssuedAt:   now,
		Expiration: now + tc.Expiration,
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     []*JwtResourceAccess{},
	}
	for _, a := range ares {
		ra := &JwtResourceAccess{
			Type:    a.Scope.Type,
			Name:    a.Scope.Name,
			Actions: a.AutorizedActions,
		}
		if ra.Actions == nil {
			ra.Actions = []string{}
		}
		sort.Strings(ra.Actions)
		claims.Access = append(claims.Access, ra)
	}
	claimsJSON := utils.ToJson(claims)

	payload := fmt.Sprintf("%s%s%s", as.jwt.EncodeSegment([]byte(headerJSON)), TokenSeparator, as.jwt.EncodeSegment([]byte(claimsJSON)))
	return payload, sigAlg, nil
}

func (as *AuthService) CreateAuthorizationToken(ar *utils.AuthRequest, ares []utils.AuthzResult) (utils.StringMap, error) {
	payload, err := utils.RandomString(15)
	tc := &as.config.Token
	_, sigAlg, err := tc.GetPrivateKey().Sign(strings.NewReader("dummy"), 0)
	if err != nil {
		return nil, err
	}
	tokenResult := utils.StringMap{}
	if err != nil {
		return tokenResult, err
	}

	sig, sigAlg2, err := tc.GetPrivateKey().Sign(strings.NewReader(payload), 0)
	if err != nil || sigAlg2 != sigAlg {
		return tokenResult, fmt.Errorf("failed to sign token: %s", err)
	}
	tokenResult.Add("sub", ar.Account)
	tokenResult.Add("algorithm", sigAlg)
	tokenResult.Add("service", ar.Service)
	tokenResult.Add(utils.AuthorizationCodeField, utils.JsonBase64UrlEncode(sig))
	return tokenResult, nil
}

// https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md#example
func (as *AuthService) CreateOAuthToken(ar *utils.AuthRequest, ares []utils.AuthzResult) (utils.StringMap, error) {
	payload, sigAlg, err := as.GetClaims(ar, ares)
	if err != nil {
		return nil, err
	}
	glog.Infof("New token for %s %+v", *ar, ar.Labels)
	return as.GenerateJWT(payload, sigAlg)
}

// Validate a JWT token
func (as *AuthService) ValidateJWT(tokenStr, signAlg string, isAlt bool) (utils.StringMap, error) {
	parts := strings.Split(tokenStr, TokenSeparator)
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT token")
	}

	// Access token header
	headerJson, err := as.jwt.DecodeSegment(parts[0])
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
	claimJSON, err := as.jwt.DecodeSegment(parts[1])
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
	ds, _ := as.jwt.DecodeSegment(signature)
	if isAlt {
		if as.config.Token.GetAltPublicKey() != nil {
			return nil, errors.New("invalid refresh token key")
		}
		err = as.config.Token.GetAltPublicKey().Verify(strings.NewReader(payload), header.SigningAlg, ds)
		if err != nil {
			m := "invalid signature"
			glog.V(2).Infof("%s:%v", m, err)
			return nil, errors.New(m)
		}
	} else {
		err = as.config.Token.GetPublicKey().Verify(strings.NewReader(payload), header.SigningAlg, ds)
		if err != nil {
			m := "invalid signature"
			glog.V(2).Infof("%s:%v", m, err)
			return nil, errors.New(m)
		}
	}
	return utils.ToStringMap(&claims), nil
}

func (as *AuthService) GenerateJWT(payload string, sigAlg string) (utils.StringMap, error) {
	tokenResult := utils.StringMap{}
	var err error
	if err != nil {
		return tokenResult, err
	}
	tc := &as.config.Token
	sig, sigAlg2, err := tc.GetPrivateKey().Sign(strings.NewReader(payload), 0)
	if err != nil || sigAlg2 != sigAlg {
		return tokenResult, fmt.Errorf("failed to sign token: %s", err)
	}
	if tc.GetAltPrivateKey() != nil {
		sigRefresh, _, err2 := tc.GetAltPrivateKey().Sign(strings.NewReader(payload), 0)
		if err2 != nil {
			return tokenResult, fmt.Errorf("failed to sign token: %s", err)
		}
		// Add access token and refresh token
		tokenResult.Add("refresh_token", fmt.Sprintf("%s%s%s", payload, TokenSeparator, as.jwt.EncodeSegment(sigRefresh)))
	}
	tokenResult.Add("access_token", fmt.Sprintf("%s%s%s", payload, TokenSeparator, as.jwt.EncodeSegment(sig)))
	return tokenResult, nil
}

func (as *AuthService) GetToken() utils.TokenConfig {
	return as.config.Token
}

func (as *AuthService) GetServerConfig() utils.ServerConfig {
	return as.config.Server
}

func (as *AuthService) GoogleAuthEnabled() bool {
	return as.ga != nil
}

func (as *AuthService) GithubAuthEnabled() bool {
	return as.gha != nil
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
