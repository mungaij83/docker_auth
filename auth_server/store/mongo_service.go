package store

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/glog"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type MongoServices struct {
	*MongoStore
}

// Create mongo services
func NewMongoServices(st *MongoStore) ServiceStore {
	serv := MongoServices{st}
	mogo.ModelRegistry.Register(models.AuthServices{}, models.SystemRealms{})
	return serv
}

func (ms MongoServices) AddSystemRealm(realm models.SystemRealms) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		docs := mogo.NewDoc(models.SystemRealms{}).(*models.SystemRealms)
		var err error
		if realm.IsDefault {
			q := make([]bson.M, 0)
			q = append(q, bson.M{"realm_name": realm.RealmName})
			q = append(q, bson.M{"is_default": true})
			err = docs.Find(bson.M{"$or": q}).One(docs)
		} else {
			err = docs.Find(bson.M{"realm_name": realm.RealmName}).One(docs)
		}

		if err == mgo.ErrNotFound {
			realmDocs := mogo.NewDoc(realm).(*models.SystemRealms)
			err = realmDocs.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = realmDocs
			}
		} else {
			if realm.IsDefault {
				result.Error = errors.New("default realm already exists")
			} else {
				result.Error = errors.New("realm already exists")
			}
			result.Success = false
		}
		st <- result
	}()
	return st
}

func (ms MongoServices) ListSystemRealm(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		realms := make([]models.SystemRealms, 0)
		realmDocs := mogo.NewDoc(models.SystemRealms{}).(*models.SystemRealms)
		err := realmDocs.Find(bson.M{}).Skip(page.Offset()).Limit(page.Size).All(&realms)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = realms
		}
		st <- result
	}()
	return st
}

func (ms MongoServices) GetSystemRealmById(realmId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(realmId) {
			result.Error = errors.New("invalid realm id")
			result.Success = false
			st <- result
			return
		}
		// Find realm
		realmDocs := mogo.NewDoc(models.SystemRealms{}).(*models.SystemRealms)
		err := realmDocs.FindByID(bson.ObjectIdHex(realmId), realmDocs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = realmDocs
		}
		st <- result
	}()
	return st
}

func (ms MongoServices) GetSystemRealmByName(realmName string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Find realm by name
		realmDocs := mogo.NewDoc(models.SystemRealms{}).(*models.SystemRealms)
		err := realmDocs.Find(bson.M{"realm_name": realmName}).One(realmDocs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			// Delete
			err = realmDocs.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = realmDocs
			}
		}
		st <- result
	}()
	return st
}

func (ms MongoServices) GetDefaultSystemRealm() (*models.SystemRealms, error) {
	// Find realm by name
	realmDocs := mogo.NewDoc(models.SystemRealms{}).(*models.SystemRealms)
	err := realmDocs.Find(bson.M{"is_default": true}).One(realmDocs)
	if err != nil {
		return nil, err
	}
	return realmDocs, nil
}

func (ms MongoServices) DeleteSystemRealm(realmId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(realmId) {
			result.Error = errors.New("invalid realm id")
			result.Success = false
			st <- result
			return
		}
		// Find realm
		realmDocs := mogo.NewDoc(models.SystemRealms{}).(*models.SystemRealms)
		err := realmDocs.FindByID(bson.ObjectIdHex(realmId), realmDocs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else if realmDocs.IsDefault {
			result.Error = errors.New("default realm cannot be deleted")
			result.Success = false
		} else {
			// Delete
			err = realmDocs.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = realmDocs
			}
		}
		st <- result
	}()
	return st
}

func (ms MongoServices) ListServices(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		var services [] models.AuthServices
		docs := ms.GetDocument(nil)
		err := docs.Find(bson.M{}).Skip(page.Offset()).Limit(page.Size).All(&services)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = services
		}
		st <- result
	}()
	return st
}

func (ms MongoServices) GetDocument(s *models.AuthServices) *models.AuthServices {
	if s != nil {
		return mogo.NewDoc(&s).(*models.AuthServices)
	} else {
		return mogo.NewDoc(models.AuthServices{}).(*models.AuthServices)
	}
}
func (ms MongoServices) AddUser(userId, serviceId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		st <- result
	}()
	return st
}

func (ms MongoServices) RemoveUser(userId, serviceId string) DataChannel {
	panic("implement me")
}

func (ms MongoServices) AddService(serv models.AuthServices) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		docs := mogo.NewDoc(serv).(*models.AuthServices)
		err := docs.Save()
		if err != nil {
			result.Success = false
			result.Error = err
		} else {
			result.Data = docs
		}
		st <- result
	}()
	return st
}

func (ms MongoServices) RemoveService(serviceId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(serviceId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid service %v", serviceId)
			st <- result
			return
		}
		// Find and delete
		id := bson.ObjectIdHex(serviceId)
		docs := ms.GetDocument(nil)
		err := docs.FindID(id).One(docs)
		if err != nil {
			glog.V(2).Infof("failed to get service[%v]: %v", id, err)
			result.Error = err
			result.Success = false
		} else {
			err = docs.Remove()
			if err != nil {
				glog.V(2).Infof("failed to delete service: %v", err)
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

func (ms MongoServices) ServiceById(serviceId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()

		service, err := ms.GetServiceById(serviceId)
		if err != nil {
			glog.V(2).Infof("failed to get service: %v", err)
			result.Error = err
			result.Success = false
		} else {
			result.Data = service
		}
		st <- result
	}()
	return st
}

func (ms MongoServices) GetServiceById(serviceId string) (*models.AuthServices, error) {
	if !bson.IsObjectIdHex(serviceId) {
		return nil, fmt.Errorf("invalid service %v", serviceId)
	}
	// Find and delete
	id := bson.ObjectIdHex(serviceId)
	var service models.AuthServices
	docs := ms.GetDocument(&service)
	err := docs.FindID(id).One(&service)
	return docs, err
}

func (ms MongoServices) GetServiceByName(serviceName string) (*models.AuthServices, error) {
	var service models.AuthServices
	docs := ms.GetDocument(&service)
	err := docs.FindID(bson.M{"service_name": serviceName}).One(&service)
	return docs, err
}

func (ms MongoServices) UpdateService(id string, serv models.AuthServices) DataChannel {
	panic("implement me")
}
