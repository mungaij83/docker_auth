package store

import (
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/goonode/mogo"
)

type MongoTokenStore struct {
	*MongoStore
}

// Init token store
func NewMongoTokenStore(st *MongoStore) TokenStore {
	tokens := MongoTokenStore{st}
	mogo.ModelRegistry.Register(models.Token{})
	return tokens
}

func (ts MongoTokenStore) GetToken(token string, serviceRef string) DataChannel {
	panic("implement me")
}

func (ts MongoTokenStore) AddToken(token models.Token) DataChannel {
	panic("implement me")
}

func (ts MongoTokenStore) RemoveToken(token, serviceRef string) DataChannel {
	panic("implement me")
}
