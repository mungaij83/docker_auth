package utils

import (
	"fmt"
	"plugin"
)

type PluginAuthzConfig struct {
	PluginPath string `yaml:"plugin_path"`
}

func LookupAuthzSymbol(cfg *PluginAuthzConfig) (Authorizer, error) {
	// load module
	plug, err := plugin.Open(cfg.PluginPath)
	if err != nil {
		return nil, fmt.Errorf("error while loading authz plugin: %v", err)
	}

	// look up for Authz
	symAuthen, err := plug.Lookup("Authz")
	if err != nil {
		return nil, fmt.Errorf("error while loading authz exporting the variable: %v", err)
	}

	// assert that loaded symbol is of a desired type
	var authz Authorizer
	authz, ok := symAuthen.(Authorizer)
	if !ok {
		return nil, fmt.Errorf("unexpected type from module symbol. Unable to cast Authz module")
	}
	return authz, nil
}

func (c *PluginAuthzConfig) Validate() error {
	_, err := LookupAuthzSymbol(c)
	return err
}
