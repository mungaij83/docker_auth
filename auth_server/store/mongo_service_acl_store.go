package store

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type MongoServiceAclStore struct {
	*MongoStore
}

// Init service store
func NewMongoServiceAclStore(st *MongoStore) ServiceAclStore {
	acl := MongoServiceAclStore{st}
	mogo.ModelRegistry.Register(models.RealmRoles{}, models.AclData{}, models.Scopes{})
	return acl
}

func (sas MongoServiceAclStore) AddRole(serviceId string, servRole models.RealmRoles) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()

		if !bson.IsObjectIdHex(serviceId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid service id: %s", serviceId)
			st <- result
			return
		}
		docs := mogo.NewDoc(models.Services{}).(*models.Services)
		err := docs.FindID(bson.ObjectIdHex(serviceId)).One(docs)
		if err != nil {
			result.Error = errors.New("invalid service")
			result.Success = false
		} else {
			servRole.ServiceRef = *docs
			servRole.ServiceId = docs.ID
			roleSrv := mogo.NewDoc(servRole).(*models.RealmRoles)
			err = roleSrv.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = roleSrv
			}
		}
		st <- result

	}()
	return st
}

func (sas MongoServiceAclStore) RemoveRole(roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()

		if !bson.IsObjectIdHex(roleId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid service id: %s", roleId)
			st <- result
			return
		}
		id := bson.ObjectIdHex(roleId)
		docs := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
		err := docs.FindID(id).One(docs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			err = docs.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = docs
			}
		}
		st <- result

	}()

	return st
}

func (sas MongoServiceAclStore) GetRoleById(roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()

		if !bson.IsObjectIdHex(roleId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid service id: %s", roleId)
			st <- result
			return
		}
		id := bson.ObjectIdHex(roleId)
		// Check role exists
		docs := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
		err := docs.FindID(id).One(docs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = docs
		}
		st <- result

	}()

	return st
}

func (sas MongoServiceAclStore) UpdateRole(id string, servRole models.RealmRoles) DataChannel {
	panic("not implemented")
}

func (sas MongoServiceAclStore) GetServiceRoles(serviceId string, page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()

		if !bson.IsObjectIdHex(serviceId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid service id: %s", serviceId)
			st <- result
			return
		}
		id := bson.ObjectIdHex(serviceId)
		docs := mogo.NewDoc(models.Services{}).(*models.Services)
		err := docs.FindID(id).One(docs)
		if err != nil {
			result.Error = errors.New("invalid service")
			result.Success = false
		} else {
			roles := make([]models.RealmRoles, 0)
			roleDocs := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
			err = roleDocs.Find(&bson.M{"service_id": id}).Skip(page.Offset()).Limit(page.Size).All(&roles)
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = roles
			}
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) AssignRole(id, userId, serviceId string) DataChannel {
	panic("implement me")
}

func (sas MongoServiceAclStore) RemoveRoleAssignment(assignmentId string) DataChannel {
	panic("implement me")
}

func (sas MongoServiceAclStore) GetUserRoles(userId string) DataChannel {
	panic("implement me")
}
