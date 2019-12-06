/*
   Copyright 2019 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package utils

import (
	"fmt"
	"plugin"
	"time"
)

// Authentication plugin interface.
type Authenticator interface {
	// Given a user name and a password (plain text), responds with the result or an error.
	// Error should only be reported if request could not be serviced, not if it should be denied.
	// A special NoMatch error is returned if the authorizer could not reach a decision,
	// e.g. none of the rules matched.
	// Another special WrongPass error is returned if the authorizer failed to authenticate.
	// Implementations must be goroutine-safe.
	Authenticate(user string, password PasswordString) (bool, Labels, error)

	// Finalize resources in preparation for shutdown.
	// When this call is made there are guaranteed to be no Authenticate requests in flight
	// and there will be no more calls made to this instance.
	Stop()

	// Human-readable name of the authenticator.
	Name() string
}

//go:generate go-bindata -pkg authn -modtime 1 -mode 420 -nocompress data/

type GitHubTeam struct {
	Id           int64               `json:"id"`
	Url          string              `json:"url,omitempty"`
	Name         string              `json:"name,omitempty"`
	Slug         string              `json:"slug,omitempty"`
	Organization *GitHubOrganization `json:"organization"`
	Parent       *ParentGitHubTeam   `json:"parent,omitempty"`
}

type GitHubOrganization struct {
	Login string `json:"login"`
	Id    int64  `json:"id,omitempty"`
}

type ParentGitHubTeam struct {
	Id   int64  `json:"id"`
	Name string `json:"name,omitempty"`
	Slug string `json:"slug,omitempty"`
}

type GitHubAuthConfig struct {
	Organization     string                `yaml:"organization,omitempty"`
	ClientId         string                `yaml:"client_id,omitempty"`
	ClientSecret     string                `yaml:"client_secret,omitempty"`
	ClientSecretFile string                `yaml:"client_secret_file,omitempty"`
	TokenDB          string                `yaml:"token_db,omitempty"`
	GCSTokenDB       *GitHubGCSStoreConfig `yaml:"gcs_token_db,omitempty"`
	HTTPTimeout      time.Duration         `yaml:"http_timeout,omitempty"`
	RevalidateAfter  time.Duration         `yaml:"revalidate_after,omitempty"`
	GithubWebUri     string                `yaml:"github_web_uri,omitempty"`
	GithubApiUri     string                `yaml:"github_api_uri,omitempty"`
	RegistryUrl      string                `yaml:"registry_url,omitempty"`
}

type GitHubGCSStoreConfig struct {
	Bucket           string `yaml:"bucket,omitempty"`
	ClientSecretFile string `yaml:"client_secret_file,omitempty"`
}

type GitHubAuthRequest struct {
	Action string `json:"action,omitempty"`
	Code   string `json:"code,omitempty"`
	Token  string `json:"token,omitempty"`
}

type GitHubTokenUser struct {
	Login string `json:"login,omitempty"`
	Email string `json:"email,omitempty"`
}

type LinkHeader struct {
	First string
	Last  string
	Next  string
	Prev  string
}

type MongoAuthConfig struct {
	MongoConfig *MongoConfig `yaml:"dial_info,omitempty"`
	Collection  string              `yaml:"collection,omitempty"`
}

// Validate ensures that any custom config options
// in a Config are set correctly.
func (c *MongoAuthConfig) Validate(configKey string) error {
	//First validate the mongo config.
	if err := c.MongoConfig.Validate(configKey); err != nil {
		return err
	}

	// Now check additional config fields.
	if c.Collection == "" {
		return fmt.Errorf("%s.collection is required", configKey)
	}

	return nil
}

type AuthUserEntry struct {
	Username *string `yaml:"username,omitempty" json:"username,omitempty"`
	Password *string `yaml:"password,omitempty" json:"password,omitempty"`
	Labels   Labels  `yaml:"labels,omitempty" json:"labels,omitempty"`
}


type PluginAuthnConfig struct {
	PluginPath string `yaml:"plugin_path"`
}

func LookupAuthnSymbol(cfg *PluginAuthnConfig) (Authenticator, error) {
	// load module
	plug, err := plugin.Open(cfg.PluginPath)
	if err != nil {
		return nil, fmt.Errorf("error while loading authn plugin: %v", err)
	}

	// look up for Authn
	symAuthen, err := plug.Lookup("Authn")
	if err != nil {
		return nil, fmt.Errorf("error while loading authn exporting the variable: %v", err)
	}

	// assert that loaded symbol is of a desired type
	var authn Authenticator
	authn, ok := symAuthen.(Authenticator)
	if !ok {
		return nil, fmt.Errorf("unexpected type from module symbol. Unable to cast Authn module")
	}
	return authn, nil
}

func (c *PluginAuthnConfig) Validate() error {
	_, err := LookupAuthnSymbol(c)
	return err
}