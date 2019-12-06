package utils

type LDAPAuthConfig struct {
	Addr                  string              `yaml:"addr,omitempty"`
	TLS                   string              `yaml:"tls,omitempty"`
	InsecureTLSSkipVerify bool                `yaml:"insecure_tls_skip_verify,omitempty"`
	CACertificate         string              `yaml:"ca_certificate,omitempty"`
	Base                  string              `yaml:"base,omitempty"`
	Filter                string              `yaml:"filter,omitempty"`
	GroupFilter           string              `yaml:"group_filter,omitempty"`
	BindDN                string              `yaml:"bind_dn,omitempty"`
	BindPasswordFile      string              `yaml:"bind_password_file,omitempty"`
	BindPassword          string              `yaml:"bind_password,omitempty"`
	LabelMaps             map[string]LabelMap `yaml:"labels,omitempty"`
}
