package api

import (
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/glog"
	"net/http"
)

func InitClientApi() {
	Srv.Handle("/api/client/add", app.ApiHandler(HandleCreateClient)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/clients", app.ApiHandler(HandleListClient)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}", app.ApiHandler(HandleDeleteClient)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}", app.ApiHandler(HandleGetOneClient)).Methods(http.MethodOptions, http.MethodGet)
	// AuthServices
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}/realm/add", app.ApiHandler(AddClientToRealmRole)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}/roles", app.ApiHandler(GetClientRealmRoles)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/client/realm/{client_role_id:[A-Fa-f0-9]+}", app.ApiHandler(DeleteClientRoleAssignment)).Methods(http.MethodOptions, http.MethodDelete)
	// Assignments
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}/groups", app.ApiHandler(ListClientAssignedGroups)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}/roles", app.ApiHandler(ListClientAssignedRoles)).Methods(http.MethodOptions, http.MethodGet)
}

func ListClientAssignedRoles(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListClientAssignedRoles"
	response := app.NewResultModel()
	// Get client roles
	res := <-command.DataStore.Groups().GetClientRoles(c.GetPathParam("client_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func ListClientAssignedGroups(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListClientAssignedGroups"

	response := app.NewResultModel()
	// Get groups
	res := <-command.DataStore.Groups().GetClientGroups(c.GetPathParam("client_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func DeleteClientRoleAssignment(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "DeleteClientRoleAssignment"

	response := app.NewResultModel()
	clientId := c.GetPathParam("client_role_id")
	res := <-command.DataStore.Clients().DeleteClientRole(clientId)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func GetClientRealmRoles(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetClientRealmRoles"

	response := app.NewResultModel()
	clientId := c.GetPathParam("client_id")
	res := <-command.DataStore.Clients().GetClientRoles(clientId)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddClientToRealmRole(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddClientToRealmRole"

	response := app.NewResultModel()
	// Add service clients
	var clientRole models.ClientRealmRoles
	clientRole.Active = c.Data.GetBool("active")
	clientRole.Description = c.Data.GetString("description")
	clientId := c.GetPathParam("client_id")
	serviceId := c.Data.GetString("service_id")
	glog.V(2).Infof("client[%v], service [%v]", clientId, serviceId)
	res := <-command.DataStore.Clients().AddClientRole(serviceId, clientId, clientRole)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func HandleGetOneClient(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleGetOneClient"

	response := app.NewResultModel()
	// Fetch clients
	res := <-command.DataStore.Clients().GetClientById(c.GetPathParam("client_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func HandleDeleteClient(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleDeleteClient"

	response := app.NewResultModel()
	// Fetch clients
	res := <-command.DataStore.Clients().RemoveClient(c.GetPathParam("client_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func HandleListClient(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleListClient"

	response := app.NewResultModel()
	// Fetch clients
	res := <-command.DataStore.Clients().ListClients(c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func HandleCreateClient(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleCreateClient"
	response := app.NewResultModel()
	var clientDetails models.Clients
	clientDetails.ClientName = c.Data.GetString("client_name")
	clientDetails.Active = c.Data.GetBool("active")
	clientDetails.ClientType = c.Data.GetString("client_type")
	clientDetails.Description = c.Data.GetString("description")
	clientDetails.DynamicRedirect = c.Data.GetBool("dynamic_redirect")
	clientDetails.RedirectUri = c.Data.GetString("redirect_uri")
	clientDetails.BaseUri = c.Data.GetString("base_uri")
	clientDetails.ImplicitFlowEnabled = c.Data.GetBool("implicit_flow_enabled")
	clientDetails.StandardFlowEnabled = c.Data.GetBool("standard_flow_enabled")
	clientDetails.PasswordGrantEnabled = c.Data.GetBool("password_grant_enabled")
	clientDetails.AllowAllScope = c.Data.GetBool("allow_all_scope")
	clientDetails.ClientProtocol = c.Data.GetString("auth_protocol")
	clientDetails.AppRealm = c.Data.GetString("app_realm")
	// Add client
	res := <-command.DataStore.Clients().AddClient(clientDetails)
	response.FromResult(res)
	// Write result
	app.WriteResult(w, response)
}
