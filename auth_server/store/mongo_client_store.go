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

func (cs MongoClientStore) ClientRoles(clientId string) []utils.AuthzResult {
	res := <-cs.Groups().GetClientRoles(clientId)
	if res.HasError() {
		glog.V(1).Infof("Error fetching client roles: %v", res.Error)
		return make([]utils.AuthzResult, 0)
	}
	data, ok := res.Data.([]utils.StringMap)
	if ok {
		return make([]utils.AuthzResult, 0)
	}

	return cs.ParseRoles(data, true)
}

func NewMongoClientStore(st *MongoStore) ClientStore {
	str := MongoClientStore{st}
	mogo.ModelRegistry.Register(models.Clients{}, models.ClientRealmRoles{})
	return str
}

func (cs MongoClientStore) MakeDoc() *models.Clients {
	return mogo.NewDoc(models.Clients{}).(*models.Clients)
}

func (cs MongoClientStore) DeleteClientRole(clientAssignmentId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(clientAssignmentId) {
			result.Error = fmt.Errorf("invalid client service id")
			result.Success = false
			st <- result
			return
		}
		serviceDocs := mogo.NewDoc(models.ClientRealmRoles{}).(*models.ClientRealmRoles)
		err := serviceDocs.FindByID(bson.ObjectIdHex(clientAssignmentId), serviceDocs)
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

func (cs MongoClientStore) GetClientRoles(clientId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(clientId) {
			result.Error = fmt.Errorf("invalid client id")
			result.Success = false
			st <- result
			return
		}
		clientRealmRoles := make([] models.ClientRealmRoles, 0)
		serviceDocs := mogo.NewDoc(models.ClientRealmRoles{}).(*models.ClientRealmRoles)
		err := serviceDocs.Find(bson.M{"client_id": bson.ObjectIdHex(clientId)}).All(&clientRealmRoles)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = clientRealmRoles
		}
		st <- result
	}()
	return st
}

func (cs MongoClientStore) AddClientRole(roleId string, clientId string, clientService models.ClientRealmRoles) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(roleId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid service id: %v", roleId)
			st <- result
			return
		}

		if !bson.IsObjectIdHex(clientId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid client id: %v", roleId)
			st <- result
			return
		}
		// Find client
		cId := bson.ObjectIdHex(clientId)
		clientDoc := mogo.NewDoc(models.Clients{}).(*models.Clients)
		err := clientDoc.FindByID(cId, clientDoc)
		if err != nil {
			result.Success = false
			result.Error = fmt.Errorf("client not found: %v", clientId)
			st <- result
			return
		}
		// Find role
		sId := bson.ObjectIdHex(roleId)
		roleDoc := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
		err = roleDoc.FindByID(sId, roleDoc)
		if err != nil {
			result.Error = fmt.Errorf("invalid role id")
			result.Success = false
			st <- result
			return
		}
		// Add client to role
		cService := mogo.NewDoc(clientService).(*models.ClientRealmRoles)
		cService.RoleId = roleDoc.ID
		cService.ClientId = clientDoc.ID
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

		client.ClientId = strings.ToUpper(clientId)
		// Hash secret
		h, _ := utils.NewHashParameters(false, utils.Pbkdf2Sha512, "")
		clientSecret, _ := h.RandomString(10)
		glog.V(2).Infof("Client credentials [%s]:[%s]", clientId, clientSecret)
		h.RawPassword = clientSecret
		h.Cost = 4000
		client.ClientSecret = h.Encode()
		// Save hashed password
		newDoc := mogo.NewDoc(client).(*models.Clients)
		err = newDoc.Save()
		if err != nil {
			result.Success = false
			result.Error = err
		} else {
			// Set client secret back
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

func (cs MongoClientStore) ClientById(clientId string) (*models.Clients, error) {
	if !bson.IsObjectIdHex(clientId) {
		return nil, fmt.Errorf("client id is required: %s", clientId)
	}

	client := cs.MakeDoc()
	err := client.FindByID(bson.ObjectIdHex(clientId), client)
	return client, err
}

func (cs MongoClientStore) GetClientByClientId(clientId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if len(clientId) == 0 {
			result.Error = fmt.Errorf("client id is required: %s", clientId)
			result.Success = false
			st <- result
			return
		}

		client := cs.MakeDoc()
		err := client.Find(bson.M{"client_id": clientId}).One(client)
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
