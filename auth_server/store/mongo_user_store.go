package store

import (
	"errors"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/glog"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type MongoUserStore struct {
	*MongoStore
}

func NewMongoUserStore(st *MongoStore) UserStore {
	usr := MongoUserStore{st}
	mogo.ModelRegistry.Register(models.Users{}, models.ExternalUsers{})
	return usr
}

func (us MongoUserStore) GetExternalUser(userId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Check valid id
		if !bson.IsObjectIdHex(userId) {
			result.Error = errors.New("invalid user id")
			result.Success = false
			st <- result
			return
		}
		id := bson.ObjectIdHex(userId)
		// Find document
		existDoc := mogo.NewDoc(models.ExternalUsers{}).(*models.ExternalUsers)
		err := existDoc.FindID(id).One(existDoc)
		if err != nil {
			glog.V(2).Infof("Failed to get user[%v]: %v", id, err)
			result.Error = err
			result.Success = false
		} else {
			result.Data = existDoc
		}
		st <- result
	}()
	return st
}

func (us MongoUserStore) ListExternalUsers(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		var users [] models.ExternalUsers
		docs := mogo.NewDoc(models.ExternalUsers{}).(*models.ExternalUsers)
		err := docs.Find(bson.M{}).Skip(page.Offset()).Limit(page.Size).All(&users)
		if err != nil {
			result.Error = err
		} else {
			result.Data = users
		}
		st <- result
	}()
	return st
}

func (us MongoUserStore) GetUserForLogin(username, password string) DataChannel {
	panic("implement me")
}

// Add external user to list of external users
func (us MongoUserStore) AddExternalUser(user models.ExternalUsers) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		existDoc := mogo.NewDoc(models.ExternalUsers{}).(*models.ExternalUsers)
		dd := models.ExternalUsers{}
		err := existDoc.Find(bson.M{"username": user.Username}).One(&dd)

		if err != nil {
			doc := mogo.NewDoc(user).(*models.ExternalUsers)
			err := doc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = doc
			}
		} else {
			glog.V(1).Infof("user exists: %v", err)
			result.Data = dd
		}
		st <- result
	}()
	return st
}

func (us MongoUserStore) RemoveExternalUser(userId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Check valid id
		if !bson.IsObjectIdHex(userId) {
			result.Error = errors.New("invalid user id")
			result.Success = false
			st <- result
			return
		}
		id := bson.ObjectIdHex(userId)
		// Find document
		existDoc := mogo.NewDoc(models.ExternalUsers{}).(*models.ExternalUsers)
		err := existDoc.FindID(id).One(existDoc)
		if err != nil {
			glog.V(2).Infof("Failed to get object[%v]: %v", id, err)
			result.Error = err
			result.Success = false
		} else {
			// Remove document
			err = existDoc.Remove()
			if err != nil {
				glog.V(2).Infof("Failed to delete object[%v]: %v", id, err)
				result.Error = err
				result.Success = false
			} else {
				result.Data = existDoc
			}
		}
		st <- result
	}()
	return st
}

func (us MongoUserStore) AddUser(user models.Users) DataChannel {
	panic("implement me")
}

func (us MongoUserStore) UpdateUser(id string, user models.Users) DataChannel {
	panic("implement me")
}

func (us MongoUserStore) RemoveUser(id string) DataChannel {
	panic("implement me")
}

func (us MongoUserStore) ListUsers(page Page) DataChannel {
	panic("implement me")
}
