package api

import (
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"net/http"
)

func InitRealmRolesApi() {
	// AuthServices
	Srv.Handle("/api/realm/role/add", app.ApiHandler(AddRealmRole)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/realm/roles", app.ApiHandler(ListRealmRoles)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/realm/{role_id:[a-fA-F0-9]+}", app.ApiHandler(DeleteRealmRole)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/realm/{role_id:[a-fA-F0-9]+}", app.ApiHandler(GetRealmRoleById)).Methods(http.MethodOptions, http.MethodGet)
	// Service Roles
	Srv.Handle("/api/realm/{role_id:[a-fA-F0-9]+}/permission/add", app.ApiHandler(AddRealmPermission)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/realm/{role_id:[a-fA-F0-9]+}/permissions", app.ApiHandler(GetRealmPermissions)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/realm/permission/{permission_id:[a-fA-F0-9]+}", app.ApiHandler(GetRealmPermissionById)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/realm/permission/{permission_id:[a-fA-F0-9]+}", app.ApiHandler(RemoveRealmRolePermission)).Methods(http.MethodOptions, http.MethodDelete)
	// Assign service roles

}

func GetRealmPermissionById(c *app.Context, w http.ResponseWriter, _ *http.Request) {

	c.ActionName = "GetRealmPermissionById"

	response := app.NewResultModel()
	// Get service roles
	res := <-command.DataStore.AclStore().GetRealmPermissionById(c.GetPathParam("permission_id"))
	response.FromResult(res)
	// Write result
	app.WriteResult(w, response)
}

func RemoveRealmRolePermission(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "RemoveRealmRolePermission"

	response := app.NewResultModel()
	// Get service roles
	res := <-command.DataStore.AclStore().RemoveRealmPermission(c.GetPathParam("permission_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func GetRealmPermissions(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetRealmPermissions"

	response := app.NewResultModel()
	// Get service permissions
	res := <-command.DataStore.AclStore().GetRealmPermissions(c.GetPathParam("role_id"), c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddRealmPermission(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddRealmPermission"

	response := app.NewResultModel()
	// Add permission
	var serviceRole models.RealmPermissions
	serviceRole.Description = c.Data.GetString("description")
	serviceRole.PermissionName = c.Data.GetString("permission_name")
	serviceRole.Active = c.Data.GetBool("active")
	glog.V(3).Infof("permission details: %v", utils.ToJson(serviceRole))
	res := <-command.DataStore.AclStore().AddRealmPermission(c.GetPathParam("role_id"), serviceRole)
	response.FromResult(res)

	app.WriteResult(w, response)
}

func GetRealmRoleById(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetRealmRoleById"
	response := app.NewResultModel()
	// Get realm role by id
	res := <-command.DataStore.AclStore().GetRealmRoleById(c.GetPathParam("role_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func DeleteRealmRole(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "DeleteRealmRole"
	response := app.NewResultModel()
	// Remove realm role
	res := <-command.DataStore.AclStore().RemoveRealmRole(c.GetPathParam("role_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func ListRealmRoles(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListRealmRoles"
	response := app.NewResultModel()
	// Get list of realm roles
	res := <-command.DataStore.AclStore().ListRealmRoles(c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddRealmRole(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddRealmRole"

	response := app.NewResultModel()
	var realmRoles models.RealmRoles
	realmRoles.RoleName = c.Data.GetString("role_name")
	realmRoles.Active = c.Data.GetBool("active")
	realmRoles.Description = c.Data.GetString("description")
	// Add realmRoles
	res := <-command.DataStore.AclStore().AddRealmRole(realmRoles)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}
