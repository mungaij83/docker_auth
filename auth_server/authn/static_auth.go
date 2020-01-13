/*
   Copyright 2015 Cesanta Software Ltd.

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
	"golang.org/x/crypto/bcrypt"
)

type staticUsersAuth struct {
	users map[string]*utils.Requirements
}

func NewStaticUserAuth(users map[string]*utils.Requirements) *staticUsersAuth {
	return &staticUsersAuth{users: users}
}

func (sua *staticUsersAuth) Authenticate(user string, password utils.PasswordString, realm string) (bool, *utils.PrincipalDetails, error) {
	reqs := sua.users[user]
	if reqs == nil {
		return false, nil, utils.NoMatch
	}
	if reqs.Password != nil {
		if bcrypt.CompareHashAndPassword([]byte(*reqs.Password), []byte(password)) != nil {
			return false, nil, nil
		}
	}
	roles := make([]utils.AuthzResult, 0)
	// Add assigned roles
	rawRoles := reqs.Labels.GetArray("roles")
	for _, vv := range rawRoles {
		v := utils.AuthzResult{
			Scope: utils.AuthScope{
				Type:    vv.GetString("type"),
				Name:    vv.GetString("name"),
				Actions: vv["actions"].([]string),
			},
			AutorizedActions: make([]string, 0),
		}
		roles = append(roles, v)
	}
	// Principal details
	return true, &utils.PrincipalDetails{
		Username:  user,
		Active:    true,
		RealmName: realm,
		Roles:     roles,
	}, nil
}

func (sua *staticUsersAuth) Stop() {
}

func (sua *staticUsersAuth) Name() string {
	return "static"
}
