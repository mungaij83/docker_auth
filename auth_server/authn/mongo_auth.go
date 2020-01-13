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
	"errors"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"gopkg.in/mgo.v2"
)

type MongoAuth struct {
	config     *utils.MongoAuthConfig
	session    *mgo.Session
	Collection string `yaml:"collection,omitempty"`
}

func NewMongoAuth(c *utils.MongoAuthConfig) (*MongoAuth, error) {
	return &MongoAuth{
		config: c,
	}, nil
}

func (ma *MongoAuth) Authenticate(account string, password utils.PasswordString, realm string) (bool, *utils.PrincipalDetails, error) {

	result, principal, err := ma.authenticate(account, password, realm)
	if err != nil {
		glog.Warningf("EOF error received from Mongo. Retrying connection")
		return false, nil, err
	}
	return result, principal, err

}

func (ma *MongoAuth) authenticate(account string, password utils.PasswordString, realm string) (bool, *utils.PrincipalDetails, error) {
	glog.V(2).Infof("Checking user %s against Mongo Users. DB: %s", account, realm)
	// Copy our session
	res := <-command.DataStore.Users().GetUserForLogin(account, password.String(), realm, false)
	if res.HasError() {
		return false, nil, res.Error
	}

	user, ok := res.Data.(utils.PrincipalDetails)
	if !ok {
		glog.Infof("invalid details for user: %+v", res.Data)
		return false, nil, errors.New("invalid user details")
	}
	// Get Users roles MongoDB
	user.Roles = command.DataStore.Users().GetUserRoles(user.UserId)
	// Auth success
	return true, &user, nil
}

func (ma *MongoAuth) Stop() {
	// Close connection to MongoDB database (if any)
	if ma.session != nil {
		ma.session.Close()
	}
}

func (ma *MongoAuth) Name() string {
	return "MongoDB"
}
