package utils

type Oauth2Config struct {
	TokenDb    string                  `yaml:"token_db"`
	ExpiryTime int64                   `yaml:"expiry_time"`
	Clients    map[string]ClientConfig `yaml:"clients"`
}

type ClientConfig struct {
	RedirectUrl  string    `yaml:"redirect_url"`
	ClientId     string    `yaml:"client_id"`
	ClientName   string    `yaml:"client_name"`
	ClientSecret string    `yaml:"client_secret"`
	Scopes       [] string `yaml:"scopes"`
}
