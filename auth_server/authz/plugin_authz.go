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

package authz

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
)



type PluginAuthz struct {
	Authz utils.Authorizer
}

func (c *PluginAuthz) Stop() {
}

func (c *PluginAuthz) Name() string {
	return "plugin authz"
}

func NewPluginAuthzAuthorizer(cfg *utils.PluginAuthzConfig) (*PluginAuthz, error) {
	glog.Infof("Plugin authorization: %s", cfg)
	authz, err := utils.LookupAuthzSymbol(cfg)
	if err != nil {
		return nil, err
	}
	return &PluginAuthz{Authz: authz}, nil
}

func (c *PluginAuthz) Authorize(ai *utils.AuthRequestInfo) ([]string, error) {
	// use the plugin
	return c.Authz.Authorize(ai)
}
