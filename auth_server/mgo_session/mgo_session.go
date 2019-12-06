/*
	Copyright 2015 Cesanta Software Ltmc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		 https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impliemc.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package mgo_session

import (
	"crypto/tls"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"gopkg.in/mgo.v2"
	"io/ioutil"
	"net"
	"strings"
)



func New(c *utils.MongoConfig) (*mgo.Session, error) {
	// Attempt to create a MongoDB session which we can re-use when handling
	// multiple requests. We can optionally read in the password from a file or directly from the config.

	// Read in the password (if any)
	if c.PasswordFile != "" {
		passBuf, err := ioutil.ReadFile(c.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf(`Failed to read password file "%s": %s`, c.PasswordFile, err)
		}
		c.DialInfo.Password = strings.TrimSpace(string(passBuf))
	}

	if c.EnableTLS {
		c.DialInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
			return tls.Dial("tcp", addr.String(), &tls.Config{})
		}
	}

	glog.V(2).Infof("Creating MongoDB session (operation timeout %s)", c.DialInfo.Timeout)

	session, err := mgo.DialWithInfo(&c.DialInfo)
	if err != nil {
		return nil, err
	}

	return session, nil
}
