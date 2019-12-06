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

package authn

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
)



type PluginAuthn struct {
	cfg   *utils.PluginAuthnConfig
	Authn utils.Authenticator
}

func (c *PluginAuthn) Authenticate(user string, password utils.PasswordString) (bool, utils.Labels, error) {
	// use the plugin
	return c.Authn.Authenticate(user, password)
}

func (c *PluginAuthn) Stop() {
}

func (c *PluginAuthn) Name() string {
	return "plugin auth"
}

func NewPluginAuthn(cfg *utils.PluginAuthnConfig) (*PluginAuthn, error) {
	glog.Infof("Plugin authenticator: %s", cfg)
	authn, err := utils.LookupAuthnSymbol(cfg)
	if err != nil {
		return nil, err
	}
	return &PluginAuthn{Authn: authn}, nil
}
