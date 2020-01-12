package store

import (
	"errors"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
	"time"
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

func (ts MongoTokenStore) GetToken(token string, realmRef string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		tokenDoc := mogo.NewDoc(models.Token{}).(*models.Token)
		err := tokenDoc.Find(bson.M{"system_realm": realmRef, "access_token": token}).One(tokenDoc)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			// Validate expiry
			if tokenDoc.ValidateExpiry() {
				tokenDoc.LastAccess = time.Now()
				_ = tokenDoc.Save()
				result.Data = tokenDoc

			} else {
				// Invalidate token
				tokenDoc.TokenValid = false
				tokenDoc.LastAccess = time.Now()
				_ = tokenDoc.Save()

				result.Error = errors.New("token expired")
				result.Success = false
			}
		}
		st <- result
	}()
	return st
}

func (ts MongoTokenStore) AddToken(token models.Token) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		tokenDoc := mogo.NewDoc(token).(*models.Token)
		if token.ValidateExpiry() {
			// Save token for reference
			tokenDoc.LastAccess = time.Now()
			tokenDoc.TokenValid = true
			err := tokenDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = tokenDoc
			}
		} else {
			result.Error = errors.New("token already expired")
			result.Success = false
		}

	}()

	return st
}

func (ts MongoTokenStore) RemoveToken(token, realmRef string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		tokenDoc := mogo.NewDoc(models.Token{}).(*models.Token)
		err := tokenDoc.Find(bson.M{"system_realm": realmRef, "access_token": token}).One(tokenDoc)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			// Validate expiry
			if tokenDoc.TokenValid {
				tokenDoc.TokenValid = false
				_ = tokenDoc.Save()
				result.Data = tokenDoc
			} else {
				result.Error = errors.New("token is invalid")
				result.Success = false
			}
		}
		st <- result
	}()
	return st
}
