package api

import (
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/models"
	"net/http"
)

func InitServiceApi() {
	// Services
	Srv.Handle("/api/service/add", app.ApiHandler(AddService)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/services", app.ApiHandler(ListServices)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/service/{service_id:[a-fA-F0-9]+}", app.ApiHandler(DeleteService)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/service/{service_id:[a-fA-F0-9]+}", app.ApiHandler(GetServiceById)).Methods(http.MethodOptions, http.MethodGet)
	// Service Roles
	Srv.Handle("/api/service/{service_id:[a-fA-F0-9]+}/role/add", app.ApiHandler(AddServiceRoles)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/service/{service_id:[a-fA-F0-9]+}/roles", app.ApiHandler(GetServiceRoles)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/service/role/{role_id:[a-fA-F0-9]+}", app.ApiHandler(GetServiceRoleById)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/service/role/{role_id:[a-fA-F0-9]+}", app.ApiHandler(RemoveServiceRoles)).Methods(http.MethodOptions, http.MethodDelete)
	// Assign service roles

}

func GetServiceRoleById(c *app.Context, w http.ResponseWriter, _ *http.Request) {

	c.ActionName = "GetServiceRoleById"

	response := app.NewResultModel()
	// Get service roles
	res := <-command.DataStore.AclStore().GetRoleById(c.GetPathParam("role_id"))
	response.FromResult(res)

	app.WriteResult(w, response)
}

func RemoveServiceRoles(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "RemoveServiceRoles"

	response := app.NewResultModel()
	// Get service roles
	res := <-command.DataStore.AclStore().RemoveRole(c.GetPathParam("role_id"))
	response.FromResult(res)

	app.WriteResult(w, response)
}

func GetServiceRoles(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName = "GetServiceRoles"

	response := app.NewResultModel()
	// Get service roles
	res := <-command.DataStore.AclStore().GetServiceRoles(c.GetPathParam("service_id"), c.CurrentPage)
	response.FromResult(res)

	app.WriteResult(w, response)
}

func AddServiceRoles(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName = "AddServiceRoles"

	response := app.NewResultModel()
	// Add roles
	var serviceRole models.RealmRoles
	serviceRole.Description = c.Data.GetString("description")
	serviceRole.RoleName = c.Data.GetString("role_name")
	serviceRole.Active = c.Data.GetBool("active")
	res := <-command.DataStore.AclStore().AddRole(c.GetPathParam("service_id"), serviceRole)
	response.FromResult(res)

	app.WriteResult(w, response)
}

func GetServiceById(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetServiceById"
	response := app.NewResultModel()
	// Add service
	res := <-command.DataStore.Services().GetServiceById(c.GetPathParam("service_id"))
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
	var service models.Services
	service.Active = c.Data.GetBool("active")
	service.Description = c.Data.GetString("description")
	service.ServiceName = c.Data.GetString("service_name")
	service.ServiceType = c.Data.GetString("service_type")
	service.AppRealm = c.Data.GetString("app_realm")
	// Add service
	res := <-command.DataStore.Services().AddService(service)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}
