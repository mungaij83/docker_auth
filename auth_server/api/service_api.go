package api

import (
	"github.com/cesanta/docker_auth/auth_server/api/forms"
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/models"
	"net/http"
)

func InitServiceApi() {
	// AuthServices
	Srv.Handle("/api/service/add", app.ApiHandler(AddService)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/services", app.ApiHandler(ListServices)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/service/{service_id:[a-fA-F0-9]+}", app.ApiHandler(DeleteService)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/service/{service_id:[a-fA-F0-9]+}", app.ApiHandler(GetServiceById)).Methods(http.MethodOptions, http.MethodGet)
	// Scopes
	Srv.Handle("/api/service/{service_id:[a-fA-F0-9]+}/scope/add", app.ApiHandler(AddScopeToService)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/service/{service_id:[a-fA-F0-9]+}/scopes", app.ApiHandler(ListServiceScopes)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/service/scope/{scope_id:[a-fA-F0-9]+}", app.ApiHandler(GetServiceScopeById)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/service/scope/{scope_id:[a-fA-F0-9]+}", app.ApiHandler(RemoveServiceScopes)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/service/scope/{scope_id:[a-fA-F0-9]+}/{role_id:[a-fA-F0-9]+}/add", app.ApiHandler(AddRoleToScopes)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/service/scope/{scope_id:[a-fA-F0-9]+}/{role_id:[a-fA-F0-9]+}", app.ApiHandler(RemoveRoleToScopes)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/service/scope/{scope_id:[a-fA-F0-9]+}/roles", app.ApiHandler(ListRoleInScope)).Methods(http.MethodOptions, http.MethodGet)
	// Realms
	Srv.Handle("/api/system/realm/add", app.ApiHandler(AddSystemRealm)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/system/realms", app.ApiHandler(ListSystemRealm)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/system/realm/{realm_id:[a-fA-F0-9]+}", app.ApiHandler(GetSystemRealmById)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/system/realm/{realm_id:[a-fA-F0-9]+}", app.ApiHandler(DeleteSystemRealmById)).Methods(http.MethodOptions, http.MethodDelete)

}

func ListRoleInScope(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListRoleInScope"

	response := app.NewResultModel()
	// get roles
	res := <-command.DataStore.Groups().GeScopeRoles(c.GetPathParam("scope_id"), "user")
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func RemoveRoleToScopes(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "RemoveRoleToScopes"
	response := app.NewResultModel()
	// Add role
	res := <-command.DataStore.Groups().RemoveUserRoleFromScope(c.GetPathParam("scope_id"), c.GetPathParam("role_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddRoleToScopes(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddRoleToScopes"
	response := app.NewResultModel()
	// Add role
	res := <-command.DataStore.Groups().AddUserRoleToScope(c.GetPathParam("scope_id"), c.GetPathParam("role_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func GetServiceScopeById(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName = "GetServiceScopeById"
	response := app.NewResultModel()
	// Scope
	res := <-command.DataStore.Groups().GetScope(c.GetPathParam("scope_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func RemoveServiceScopes(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "RemoveServiceScopes"
	response := app.NewResultModel()
	// Remove scope
	res := <-command.DataStore.Groups().RemoveScope(c.GetPathParam("scope_id"))
	response.FromResult(res)
	// Write result
	app.WriteResult(w, response)
}

func ListServiceScopes(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListServiceScopes"

	response := app.NewResultModel()
	// Scope listing
	res := <-command.DataStore.Groups().ListServiceScopes(c.GetPathParam("service_id"), c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddScopeToService(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddScopeToService"

	response := app.NewResultModel()
	var scopeForm forms.ScopeForm
	err := c.Data.ToStruct(&scopeForm)
	if err != nil {
		response.ResponseMessage = "invalid data"
		response.SetResponseCode(http.StatusUnprocessableEntity)
		app.WriteResult(w, response)
		return
	}
	res := <-command.DataStore.Groups().AddScope(c.GetPathParam("service_id"), scopeForm.GetScope())
	response.FromResult(res)
	app.WriteResult(w, response)
}

func DeleteSystemRealmById(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "DeleteSystemRealmById"

	response := app.NewResultModel()
	// Delete realm
	res := <-command.DataStore.Services().DeleteSystemRealm(c.GetPathParam("realm_id"))
	response.FromResult(res)
	// result
	app.WriteResult(w, response)
}

func GetSystemRealmById(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName = "GetSystemRealmById"

	response := app.NewResultModel()
	// Get realm by ID (path)
	res := <-command.DataStore.Services().GetSystemRealmById(c.GetPathParam("realm_id"))
	response.FromResult(res)
	// result
	app.WriteResult(w, response)
}

func ListSystemRealm(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListSystemRealm"

	response := app.NewResultModel()
	// List realms
	res := <-command.DataStore.Services().ListSystemRealm(c.CurrentPage)
	response.FromResult(res)
	// result
	app.WriteResult(w, response)
}

func AddSystemRealm(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddSystemRealm"

	response := app.NewResultModel()
	// Add realm
	var realm models.SystemRealms
	realm.RealmName = c.Data.GetString("realm_name")
	realm.Active = c.Data.GetBool("active")
	realm.Description = c.Data.GetString("description")
	realm.IsDefault = c.Data.GetBool("is_default")
	res := <-command.DataStore.Services().AddSystemRealm(realm)
	response.FromResult(res)
	//Result
	app.WriteResult(w, response)
}

func GetServiceById(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetServiceById"
	response := app.NewResultModel()
	// Add service
	res := <-command.DataStore.Services().ServiceById(c.GetPathParam("service_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func DeleteService(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "DeleteService"
	response := app.NewResultModel()
	// Add service
	res := <-command.DataStore.Services().RemoveService(c.GetPathParam("service_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func ListServices(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListServices"
	response := app.NewResultModel()
	// Add service
	res := <-command.DataStore.Services().ListServices(c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddService(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddService"

	response := app.NewResultModel()
	var service models.AuthServices
	service.Active = c.Data.GetBool("active")
	service.Description = c.Data.GetString("description")
	service.ServiceName = c.Data.GetString("service_name")
	service.ServiceType = c.Data.GetString("service_type")
	service.AuthMethodTag = c.Data.GetString("auth_method_tag")
	// Add service
	res := <-command.DataStore.Services().AddService(service)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}
