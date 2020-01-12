package store

import (
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/goonode/mogo"
)

type MongoCustomerStore struct {
	*MongoStore
}

func NewCustomerStore(st *MongoStore) CustomerStore {
	mogo.ModelRegistry.Register(models.Customers{})
	return MongoClientStore{st}
}
