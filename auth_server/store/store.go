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
	return !r.Success
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
	GetTableName(i interface{}) (string, error)
	Master() *mogo.Connection
	Customers() CustomerStore
	Users() UserStore
	Services() ServiceStore
	AclStore() ServiceAclStore
	Groups() GroupStore
	Tokens() TokenStore
	Clients() ClientStore
	Settings() SettingsStore
	Close() bool
}

// User store
type UserStore interface {
	GetUserForLogin(username, password, realm string, defaultAllowed bool) DataChannel
	AddUser(user models.Users) DataChannel
	UpdateUser(id string, user models.Users) DataChannel
	RemoveUser(id string) DataChannel
	GetUserById(userId string) (*models.BaseUsers, error)
	ListUsers(page Page) DataChannel
	// External accounts
	AddExternalUser(user models.BaseUsers) DataChannel
	ListExternalUsers(page Page) DataChannel
	GetExternalUser(userId string) DataChannel
	RemoveExternalUser(userId string) DataChannel
	// Extra attributes
	AddUserExtraAttribute(userId string, attribute models.UserAttributes) DataChannel
	RemoveUserExtraAttribute(userId string, attributeId string) DataChannel
}

// Service store
type ServiceStore interface {
	AddService(serv models.AuthServices) DataChannel
	RemoveService(id string) DataChannel
	UpdateService(id string, serv models.AuthServices) DataChannel

	AddSystemRealm(realm models.SystemRealms) DataChannel
	ListSystemRealm(page Page) DataChannel
	GetSystemRealmByName(string) DataChannel
	GetSystemRealmById(string) DataChannel
	GetDefaultSystemRealm() (*models.SystemRealms, error)
	DeleteSystemRealm(string) DataChannel

	AddUser(userId, serviceId string) DataChannel
	RemoveUser(userId, serviceId string) DataChannel
	ListServices(page Page) DataChannel
	GetServiceById(serviceId string) (*models.AuthServices, error)
	GetServiceByName(serviceName string) (*models.AuthServices, error)
	ServiceById(serviceId string) DataChannel
}

// ACL control
type ServiceAclStore interface {
	// Realm roles
	AddRealmRole(servRole models.RealmRoles) DataChannel
	ListRealmRoles(page Page) DataChannel
	RemoveRealmRole(roleId string) DataChannel
	UpdateRealmRole(roleId string, servRole models.RealmRoles) DataChannel
	GetRealmRoleById(roleId string) DataChannel
	GetRealmPermissions(serviceId string, page Page) DataChannel
	RealmRoleById(roleId string) (*models.RealmRoles, error)
	// Realm permissions
	AddRealmPermission(roleId string, servRole models.RealmPermissions) DataChannel
	RemoveRealmPermission(permissionId string) DataChannel
	UpdateRealmPermission(permissionId string, servRole models.RealmPermissions) DataChannel
	GetRealmPermissionById(permissionId string) DataChannel
	// User roles
	AddUserRole(usrRole models.UserRoles) DataChannel
	ListUserRoles(page Page) DataChannel
	RemoveUserRole(roleId string) DataChannel
	UpdateUserRole(roleId string, servRole models.UserRoles) DataChannel
	GetUserRoleById(roleId string) DataChannel
	GetUserRolePermissions(roleId string, page Page) DataChannel
	UserRoleById(roleId string) (*models.UserRoles, error)
	// Role permissions
	AddUserPermission(roleId string, servRole models.UserPermissions) DataChannel
	RemoveUserPermission(permissionId string) DataChannel
	UpdateUserPermission(permissionId string, servRole models.UserPermissions) DataChannel
	GetUserPermissionById(permissionId string) DataChannel
	// Assign realm Roles to clients
	AssignRole(roleId, userId, clientId string) DataChannel
	RemoveRoleAssignment(assignmentId string) DataChannel
	// Assign user roles
	AssignUserRole(userId, roleId string) DataChannel
	RemoveAssignedUserRole(assignmentId string) DataChannel

	GetUserRoles(userId string) DataChannel
}

// Groups management

type GroupStore interface {
	// Group details
	AddGroup(g models.Groups) DataChannel
	GetGroup(groupId string) DataChannel
	ListGroups(page Page) DataChannel
	RemoveGroup(groupId string) DataChannel
	// Scopes
	AddScope(serviceId string, scope models.Scope) DataChannel
	ListServiceScopes(serviceId string, page Page) DataChannel
	RemoveScope(scopeId string) DataChannel
	GetScopeById(scopeId string) (*models.Scope, error)
	GetScope(scopeId string) DataChannel
	GeScopeRoles(scopeId string, gType string) DataChannel
	// Role to scope
	AddUserRoleToScope(scopeId, roleId string) DataChannel
	RemoveUserRoleFromScope(scopeId, roleId string) DataChannel
	// Realm roles
	AssignRealmRole(groupId string, roleId string, realmAssignment models.GroupRealmRoles) DataChannel
	RemoveRealmRole(assignmentId string) DataChannel
	// User Roles
	AssignUserRole(groupId string, roleId string, roleAssignment models.GroupUserRoles) DataChannel
	RemoveUserRole(assignmentId string) DataChannel
	GetUserRoles(userId string) DataChannel
	GetGroupRoles(groupId string, groupType string) DataChannel
	//Attributes
	AddAttributeOrUpdate(groupId string, attr models.GroupAttributes) DataChannel
	RemoveAttribute(attrId string, groupId string) DataChannel
	// User Assignment
	AddUser(userId string, groupId string, userGroup models.UserGroups) DataChannel
	RemoveUserAssignment(assignmentId string) DataChannel
	GetUserGroups(userId string) DataChannel
	// Client assignment
	AddClient(clientId, groupId string, assignment models.ClientGroups) DataChannel
	RemoveClientAssignment(assignmentId string) DataChannel
	GetClientGroups(clientId string) DataChannel
	GetClientRoles(clientId string) DataChannel
}
type ClientStore interface {
	AddClient(client models.Clients) DataChannel
	RemoveClient(clientId string) DataChannel
	ListClients(page Page) DataChannel
	UpdateClient(clientId string, client models.Clients) DataChannel
	GetClientById(clientId string) DataChannel
	ClientById(clientId string) (*models.Clients, error)
	GetClientByClientId(clientId string) DataChannel
	// Roles
	AddClientRole(roleId string, clientId string, clientService models.ClientRealmRoles) DataChannel
	GetClientRoles(clientId string) DataChannel
	DeleteClientRole(clientServiceId string) DataChannel
}

type CustomerStore interface {
}

// System settings
type SettingsStore interface {
	AddAuthenticationProtocol(protocol models.AuthenticationProtocol) DataChannel
	ListAuthenticationProtocol(page Page) DataChannel
	GetAuthenticationProtocol(protocolId string) DataChannel
	// Extra Attributes
	AddExtraAttributeField(fld models.ExtraAttributeFields) DataChannel
	ListExtraAttributeFields(applicationZone string, page Page) DataChannel
	RemoveExtraAttribute(attrId string) DataChannel
	// Password policy
	AddPasswordPolicy(policy models.PasswordPolicy) DataChannel
	ListPasswordPolicies(page Page) DataChannel
	RemovePasswordPolicy(policyId string) DataChannel
	// Authentication settings
	AddUpdateAuthenticationSettings(autSetting models.AuthenticationSetting) DataChannel
	GetAuthenticationSetting(page Page) DataChannel
	RemoveAuthenticationSettings(authSettingId string) DataChannel
}
