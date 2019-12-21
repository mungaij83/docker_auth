package store

import (
	"crypto/tls"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"github.com/globalsign/mgo"
	"github.com/goonode/mogo"
	"net"
	"strings"
)

type MongoStore struct {
	conn        *mogo.Connection
	usrStore    UserStore
	srvStore    ServiceStore
	aclStore    ServiceAclStore
	tokenStore  TokenStore
	clientStore ClientStore
}

// Init mongo store
func NewMongoStore(c *utils.MongoConfig) (Store, error) {
	glog.Infof("Config: %s", utils.ToJson(c))
	conn, err := CreateSession(c)
	if err != nil {
		return nil, err
	}

	st := MongoStore{conn: conn}
	st.usrStore = NewMongoUserStore(&st)
	st.srvStore = NewMongoServices(&st)
	st.aclStore = NewMongoServiceAclStore(&st)
	st.tokenStore = NewMongoTokenStore(&st)
	st.clientStore = NewMongoClientStore(&st)
	return st, nil
}

func (mn MongoStore) Clients() ClientStore {
	return mn.clientStore
}

func (mn MongoStore) Tokens() TokenStore {
	return mn.tokenStore
}

func (mn MongoStore) AclStore() ServiceAclStore {
	return mn.aclStore
}

func (mn MongoStore) Services() ServiceStore {
	return mn.srvStore
}

func (mn MongoStore) Users() UserStore {
	return mn.usrStore
}

func (mn MongoStore) Close() bool {
	defer mn.conn.Session.Close()
	return true
}

func (mn MongoStore) Master() *mogo.Connection {
	return mn.conn
}

// Create user store
func CreateSession(c *utils.MongoConfig) (*mogo.Connection, error) {
	// Attempt to create a MongoDB session which we can re-use when handling
	// multiple requests. We can optionally read in the password from a file or directly from the config.

	// Read in the password (if any)
	config := &mogo.Config{
		DialInfo: &c.DialInfo,
		Database: c.DatabaseName,
	}
	if c.MongoPassword != "" {
		c.DialInfo.Password = strings.TrimSpace(c.MongoPassword)
	}

	if c.EnableTLS {
		c.DialInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
			return tls.Dial("tcp", addr.String(), &tls.Config{})
		}
	}

	glog.V(2).Infof("Creating MongoDB session (operation timeout %s)", c.DialInfo.Timeout)

	session, err := mogo.Connect(config)
	if err != nil {
		return nil, err
	}

	return session, nil
}
