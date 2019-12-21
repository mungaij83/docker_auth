package store

import (
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/glog"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type MongoServices struct {
	*MongoStore
}

// Create mongo services
func NewMongoServices(st *MongoStore) ServiceStore {
	serv := MongoServices{st}
	mogo.ModelRegistry.Register(models.Services{})
	return serv
}

func (ms MongoServices) ListServices(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		var services [] models.Services
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

func (ms MongoServices) GetDocument(s *models.Services) *models.Services {
	if s != nil {
		return mogo.NewDoc(&s).(*models.Services)
	} else {
		return mogo.NewDoc(models.Services{}).(*models.Services)
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

func (ms MongoServices) AddService(serv models.Services) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		docs := mogo.NewDoc(serv).(*models.Services)
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

func (ms MongoServices) GetServiceById(serviceId string) DataChannel {
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
		var service models.Services
		docs := ms.GetDocument(&service)
		err := docs.FindID(id).One(&service)
		if err != nil {
			glog.V(2).Infof("failed to get service[%v]: %v", id, err)
			result.Error = err
			result.Success = false
		} else {
			result.Data = service
		}
		st <- result
	}()
	return st
}

func (ms MongoServices) UpdateService(id string, serv models.Services) DataChannel {
	panic("implement me")
}
