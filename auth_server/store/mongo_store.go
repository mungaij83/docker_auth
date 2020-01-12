package store

import (
	"crypto/tls"
	"errors"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"github.com/globalsign/mgo"
	"github.com/goonode/mogo"
	"net"
	"strings"
)

type MongoStore struct {
	conn          *mogo.Connection
	usrStore      UserStore
	aclStore      ServiceAclStore
	serviceStore  ServiceStore
	tokenStore    TokenStore
	customerStore CustomerStore
	clientStore   ClientStore
	settingStore  SettingsStore
	groupStore    GroupStore
}

// Init mongo store
func NewMongoStore(c *utils.MongoConfig) (Store, error) {
	glog.Infof("Config: %s", utils.ToJson(c))
	conn, err := CreateSession(c)
	if err != nil {
		return nil, err
	}

	st := MongoStore{conn: conn}
	st.customerStore = NewCustomerStore(&st)
	st.usrStore = NewMongoUserStore(&st)
	st.aclStore = NewMongoServiceAclStore(&st)
	st.groupStore = NewMongoGroupStore(&st)
	st.serviceStore = NewMongoServices(&st)
	st.tokenStore = NewMongoTokenStore(&st)
	st.clientStore = NewMongoClientStore(&st)
	st.settingStore = NewMongoSettingsStore(&st)
	return st, nil
}
func (nm MongoStore) GetTableName(i interface{}) (string, error) {
	_, intp, ok := mogo.ModelRegistry.Exists(i)
	if ok {
		return intp.Collection, nil
	}
	return "", errors.New("not registered")

}
func (mn MongoStore) Customers() CustomerStore {
	return mn.customerStore
}

func (mn MongoStore) Clients() ClientStore {
	return mn.clientStore
}

func (mn MongoStore) Tokens() TokenStore {
	return mn.tokenStore
}

func (mm MongoStore) Services() ServiceStore {
	return mm.serviceStore
}

func (mn MongoStore) AclStore() ServiceAclStore {
	return mn.aclStore
}

func (mn MongoStore) Groups() GroupStore {
	return mn.groupStore
}
func (mn MongoStore) Users() UserStore {
	return mn.usrStore
}

func (mm MongoStore) Settings() SettingsStore {
	return mm.settingStore
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
