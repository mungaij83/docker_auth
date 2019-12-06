package utils

import (
	"fmt"
	"gopkg.in/mgo.v2"
	"time"
)

// Config stores how to connect to the MongoDB server and an optional password file
type MongoConfig struct {
	DialInfo     mgo.DialInfo `yaml:",inline"`
	PasswordFile string       `yaml:"password_file,omitempty"`
	EnableTLS    bool         `yaml:"enable_tls,omitempty"`
}

// Validate ensures the most common fields inside the mgo.DialInfo portion of
// a Config are set correctly as well as other fields inside the
// Config itself.
func (c *MongoConfig) Validate(configKey string) error {
	if len(c.DialInfo.Addrs) == 0 {
		return fmt.Errorf("At least one element in %s.dial_info.addrs is required", configKey)
	}
	if c.DialInfo.Timeout == 0 {
		c.DialInfo.Timeout = 10 * time.Second
	}
	if c.DialInfo.Database == "" {
		return fmt.Errorf("%s.dial_info.database is required", configKey)
	}
	return nil
}

type ACLMongoConfig struct {
	MongoConfig *MongoConfig `yaml:"dial_info,omitempty"`
	Collection  string              `yaml:"collection,omitempty"`
	CacheTTL    time.Duration       `yaml:"cache_ttl,omitempty"`
}

// Validate ensures that any custom config options
// in a Config are set correctly.
func (c *ACLMongoConfig) Validate(configKey string) error {
	//First validate the MongoDB config.
	if err := c.MongoConfig.Validate(configKey); err != nil {
		return err
	}

	// Now check additional config fields.
	if c.Collection == "" {
		return fmt.Errorf("%s.collection is required", configKey)
	}
	if c.CacheTTL < 0 {
		return fmt.Errorf("%s.cache_ttl is required (e.g. \"1m\" for 1 minute)", configKey)
	}

	return nil
}
