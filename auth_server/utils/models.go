package utils

import (
	"net"
)

type AuthRequest struct {
	RemoteConnAddr string
	RemoteAddr     string
	RemoteIP       net.IP
	User           string
	Password       PasswordString
	Account        string
	Service        string
	Scopes         []AuthScope
	Labels         Labels
}
type AuthDetails struct {
	Username          string
	Password          string
	ClientId          string
	ClientSecret      string
	Scope             string
	AuthorizationCode string
	ResponseType      string
	RemoteAddress     string
	Validation        bool
}

type TokenDetails struct {
	ClientId     string
	RequestType  string
	AccessToken  string
	RefreshToken string
	ServiceName  string
}

func (a AuthDetails) Validate() (StringMap, bool) {
	errorList := StringMap{}
	if len(a.ClientId) <= 0 {
		errorList.Add("client_id", "Invalid client id")
	}

	if !a.Validation && len(a.ClientSecret) <= 0 {
		errorList.Add("client_secret", "Please provide client secret")
	}

	if !a.Validation && len(a.Password) <= 0 {
		errorList.Add("password", "Please enter password")
	}

	if !a.Validation && len(a.Username) <= 0 {
		errorList.Add("password", "Please enter username")
	}
	if len(a.ResponseType) <= 0 {
		errorList.Add("response_type", "Invalid response type")
	}
	return errorList, len(errorList) == 0
}

type AuthScope struct {
	Type    string
	Name    string
	Actions []string
}

type AuthzResult struct {
	Scope            AuthScope
	AutorizedActions []string
}

type Labels map[string][]string

type PasswordString string

func (ps PasswordString) String() string {
	if len(ps) == 0 {
		return ""
	}
	return "***"
}

type GoogleAuthRequest struct {
	Action string `json:"action,omitempty"`
	Code   string `json:"code,omitempty"`
	Token  string `json:"token,omitempty"`
}

// From github.com/google-api-go-client/oauth2/v2/oauth2-gen.go
type GoogleTokenInfo struct {
	// AccessType: The access type granted with this token. It can be
	// offline or online.
	AccessType string `json:"access_type,omitempty"`

	// Audience: Who is the intended audience for this token. In general the
	// same as issued_to.
	Audience string `json:"audience,omitempty"`

	// Email: The email address of the user. Present only if the email scope
	// is present in the request.
	Email string `json:"email,omitempty"`

	// ExpiresIn: The expiry time of the token, as number of seconds left
	// until expiry.
	ExpiresIn int64 `json:"expires_in,omitempty"`

	// IssuedTo: To whom was the token issued to. In general the same as
	// audience.
	IssuedTo string `json:"issued_to,omitempty"`

	// Scope: The space separated list of scopes granted to this token.
	Scope string `json:"scope,omitempty"`

	// TokenHandle: The token handle associated with this token.
	TokenHandle string `json:"token_handle,omitempty"`

	// UserId: The obfuscated user id.
	UserId string `json:"user_id,omitempty"`

	// VerifiedEmail: Boolean flag which is true if the email address is
	// verified. Present only if the email scope is present in the request.
	VerifiedEmail bool `json:"verified_email,omitempty"`

	// Returned in case of error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// CodeToTokenResponse is sent by Google servers in response to the grant_type=authorization_code request.
type CodeToTokenResponse struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`

	// Returned in case of error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// CodeToTokenResponse is sent by Google servers in response to the grant_type=refresh_token request.
type RefreshTokenResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	TokenType   string `json:"token_type,omitempty"`

	// Returned in case of error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ProfileResponse is sent by the /userinfo/v2/me endpoint.
// We use it to validate access token and (re)verify the email address associated with it.
type ProfileResponse struct {
	Email         string `json:"email,omitempty"`
	VerifiedEmail bool   `json:"verified_email,omitempty"`
	// There are more fields, but we only need email.
}

type LabelMap struct {
	Attribute string `yaml:"attribute,omitempty"`
	ParseCN   bool   `yaml:"parse_cn,omitempty"`
}
