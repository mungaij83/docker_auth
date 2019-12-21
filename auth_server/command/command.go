package command

import (
	"errors"
	"github.com/cesanta/docker_auth/auth_server/store"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
)

var DataStore store.Store

// Initialize database
func InitCommand(config *utils.Config) (err error) {
	if config.MongoAuth == nil {
		err = errors.New("mongo configurations missing")
		return
	}
	glog.Infof("Config(21): %+v",config.MongoAuth)
	if config.MongoAuth.MongoConfig == nil {
		err = errors.New("invalid config model")
		return
	}
	glog.Infof("Config(22): %+v",config.MongoAuth.MongoConfig)
	DataStore, err = store.NewMongoStore(config.MongoAuth.MongoConfig)
	return
}
