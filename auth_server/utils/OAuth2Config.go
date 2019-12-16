package utils

// Type of client as in RFC 6749
const (
	ConfidentialClient = "confidential"
	PublicClient       = "public"
)

type Oauth2Config struct {
	TokenDb    string                  `yaml:"token_db"`
	ExpiryTime int64                   `yaml:"expiry_time"`
	Clients    map[string]ClientConfig `yaml:"clients"`
}

type ClientConfig struct {
	RedirectUrl  string    `yaml:"redirect_url"` // Client redirection URI
	ClientId     string    `yaml:"client_id"`
	ClientName   string    `yaml:"client_name"`
	ClientSecret string    `yaml:"client_secret"`
	ClientType   string    `yaml:"client_type,omitempty"` // Client type
	Scopes       [] string `yaml:"scopes"`
}
