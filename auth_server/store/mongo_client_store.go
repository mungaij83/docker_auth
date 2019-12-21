package store

import (
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
	"strings"
)

type MongoClientStore struct {
	*MongoStore
}

func NewMongoClientStore(st *MongoStore) ClientStore {
	str := MongoClientStore{st}
	mogo.ModelRegistry.Register(models.Clients{}, models.ClientServices{})
	return str
}

func (cs MongoClientStore) MakeDoc() *models.Clients {
	return mogo.NewDoc(models.Clients{}).(*models.Clients)
}

func (cs MongoClientStore) DeleteClientServices(clientServiceId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(clientServiceId) {
			result.Error = fmt.Errorf("invalid client service id")
			result.Success = false
			st <- result
			return
		}
		serviceDocs := mogo.NewDoc(models.ClientServices{}).(*models.ClientServices)
		err := serviceDocs.FindByID(bson.ObjectIdHex(clientServiceId), serviceDocs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			err = serviceDocs.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = serviceDocs
			}
		}
		st <- result
	}()
	return st
}

func (cs MongoClientStore) GetClientServices(clientId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(clientId) {
			result.Error = fmt.Errorf("invalid client id")
			result.Success = false
			st <- result
			return
		}
		clientServices := make([] models.ClientServices, 0)
		serviceDocs := mogo.NewDoc(models.ClientServices{}).(*models.ClientServices)
		err := serviceDocs.Find(bson.M{"client_id": bson.ObjectIdHex(clientId)}).All(&clientServices)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = clientServices
		}
		st <- result
	}()
	return st
}

func (cs MongoClientStore) AddService(serviceId string, clientId string, clientService models.ClientServices) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(serviceId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid service id: %v", serviceId)
			st <- result
			return
		}

		if !bson.IsObjectIdHex(clientId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid client id: %v", serviceId)
			st <- result
			return
		}
		cId := bson.ObjectIdHex(clientId)
		clientDoc := mogo.NewDoc(models.Clients{}).(*models.Clients)
		err := clientDoc.FindByID(cId, clientDoc)
		if err != nil {
			result.Success = false
			result.Error = fmt.Errorf("client not found: %v", clientId)
			st <- result
			return
		}
		// Find service
		sId := bson.ObjectIdHex(serviceId)
		serviceDoc := mogo.NewDoc(models.Services{}).(*models.Services)
		err = serviceDoc.FindByID(sId, serviceDoc)
		if err != nil {
			result.Error = fmt.Errorf("invalid service id")
			result.Success = false
			st <- result
			return
		}
		// Add client to service
		cService := mogo.NewDoc(clientService).(*models.ClientServices)
		cService.ServiceId = serviceDoc.ID
		cService.ServiceRef = serviceDoc
		cService.ClientId = clientDoc.ID
		cService.ClientRef = clientDoc
		err = cService.Save()
		if err != nil {
			glog.V(2).Infof("error saving: %v", err)
			result.Error = err
			result.Success = false
		} else {
			result.Data = cService
		}
		st <- result
	}()
	return st
}
func (cs MongoClientStore) AddClient(client models.Clients) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		clientId, err := utils.RandomString(15, false)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		clientSecret, err := utils.RandomString(10, true)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		glog.V(2).Infof("[%s]:[%s]", clientId, clientSecret)
		client.ClientId = strings.ToUpper(clientId)
		client.ClientSecret = clientSecret
		newDoc := mogo.NewDoc(client).(*models.Clients)
		err = newDoc.Save()
		if err != nil {
			result.Success = false
			result.Error = err
		} else {
			client.ClientSecret = clientSecret
			result.Data = client
		}
		st <- result
	}()
	return st
}

func (cs MongoClientStore) GetClientById(clientId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(clientId) {
			result.Error = fmt.Errorf("invalid client id: %s", clientId)
			result.Success = false
			st <- result
			return
		}
		id := bson.ObjectIdHex(clientId)
		client := cs.MakeDoc()
		err := client.FindID(id).One(client)
		if err != nil {
			glog.V(2).Infof("failed to find client: %v", err)
			result.Error = err
			result.Success = false
		} else {
			result.Data = client
		}
		st <- result
	}()
	return st
}

func (cs MongoClientStore) RemoveClient(clientId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(clientId) {
			result.Error = fmt.Errorf("invalid client id: %s", clientId)
			result.Success = false
			st <- result
			return
		}
		id := bson.ObjectIdHex(clientId)
		client := cs.MakeDoc()
		err := client.FindID(id).One(client)
		if err != nil {
			glog.V(2).Infof("failed to find client: %v", err)
			result.Error = err
			result.Success = false
		} else {
			err = client.Remove()
			if err != nil {
				glog.V(2).Infof("failed to find client: %v", err)
				result.Error = err
				result.Success = false
			} else {
				result.Data = client
			}
		}
		st <- result
	}()
	return st
}

func (cs MongoClientStore) ListClients(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		var clients []models.Clients
		docs := mogo.NewDoc(models.Clients{}).(*models.Clients)
		err := docs.Find(bson.M{}).Skip(page.Offset()).Limit(page.Size).All(&clients)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = clients
		}
		st <- result
	}()
	return st
}

func (cs MongoClientStore) UpdateClient(clientId string, client models.Clients) DataChannel {
	panic("implement me")
}
