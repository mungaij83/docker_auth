package utils

type GoogleAuthConfig struct {
	Domain           string `yaml:"domain,omitempty"`
	ClientId         string `yaml:"client_id,omitempty"`
	ClientSecret     string `yaml:"client_secret,omitempty"`
	ClientSecretFile string `yaml:"client_secret_file,omitempty"`
	TokenDB          string `yaml:"token_db,omitempty"`
	HTTPTimeout      int    `yaml:"http_timeout,omitempty"`
}
