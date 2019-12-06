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

func (sua *staticUsersAuth) Authenticate(user string, password utils.PasswordString) (bool, utils.Labels, error) {
	reqs := sua.users[user]
	if reqs == nil {
		return false, nil, utils.NoMatch
	}
	if reqs.Password != nil {
		if bcrypt.CompareHashAndPassword([]byte(*reqs.Password), []byte(password)) != nil {
			return false, nil, nil
		}
	}
	return true, reqs.Labels, nil
}

func (sua *staticUsersAuth) Stop() {
}

func (sua *staticUsersAuth) Name() string {
	return "static"
}
