package store

import (
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/goonode/mogo"
)

// Data pagination
type Page struct {
	Size int
	Page int
}

func (p Page) Offset() int {
	return p.Page * p.Size
}

// Result from store
type ResultStore struct {
	Data    interface{}
	Error   error
	Success bool
}

func (r ResultStore) HasError() bool {
	if r.Error != nil {
		return true
	}
	return r.Success
}
func NewResultStore() ResultStore {
	return ResultStore{Success: true}
}

// Channel
type DataChannel chan ResultStore
type TokenStore interface {
	GetToken(token string, serviceRef string) DataChannel
	AddToken(token models.Token) DataChannel
	RemoveToken(token, serviceRef string) DataChannel
}

// Base store service
type Store interface {
	Master() *mogo.Connection
	Users() UserStore
	Services() ServiceStore
	AclStore() ServiceAclStore
	Tokens() TokenStore
	Clients() ClientStore
	Close() bool
}

// User store
type UserStore interface {
	GetUserForLogin(username, password string) DataChannel
	AddUser(user models.Users) DataChannel
	UpdateUser(id string, user models.Users) DataChannel
	RemoveUser(id string) DataChannel
	ListUsers(page Page) DataChannel

	AddExternalUser(user models.ExternalUsers) DataChannel
	ListExternalUsers(page Page) DataChannel
	GetExternalUser(userId string) DataChannel
	RemoveExternalUser(userId string) DataChannel
}

// Service store
type ServiceStore interface {
	AddService(serv models.Services) DataChannel
	RemoveService(id string) DataChannel
	UpdateService(id string, serv models.Services) DataChannel

	AddUser(userId, serviceId string) DataChannel
	RemoveUser(userId, serviceId string) DataChannel
	ListServices(page Page) DataChannel
	GetServiceById(serviceId string) DataChannel
}

// ACL control
type ServiceAclStore interface {
	AddRole(serviceId string, servRole models.RealmRoles) DataChannel
	RemoveRole(id string) DataChannel
	UpdateRole(id string, servRole models.RealmRoles) DataChannel
	GetRoleById(roleId string) DataChannel
	GetServiceRoles(serviceId string,page Page) DataChannel

	AssignRole(id, userId, serviceId string) DataChannel
	RemoveRoleAssignment(assignmentId string) DataChannel
	GetUserRoles(userId string) DataChannel
}

type ClientStore interface {
	AddClient(client models.Clients) DataChannel
	RemoveClient(clientId string) DataChannel
	ListClients(page Page) DataChannel
	UpdateClient(clientId string, client models.Clients) DataChannel
	GetClientById(clientId string) DataChannel
	// Services
	AddService(serviceId string,clientId string, clientService models.ClientServices) DataChannel
	GetClientServices(clientId string) DataChannel
	DeleteClientServices(clientServiceId string) DataChannel
}
