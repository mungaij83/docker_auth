package api

import (
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/models"
	"net/http"
)

func InitUserRolesApi() {
	// User roles
	Srv.Handle("/api/user/role/add", app.ApiHandler(AddUserRole)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/user/roles", app.ApiHandler(ListUserRoles)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/user/role/{role_id:[a-fA-F0-9]+}", app.ApiHandler(GetUserRoleById)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/user/role/{role_id:[a-fA-F0-9]+}", app.ApiHandler(DeleteUserRoleById)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/user/role/{role_id:[a-fA-F0-9]+}/permissions", app.ApiHandler(UserRolePermissions)).Methods(http.MethodOptions, http.MethodGet)
	// User role permissions
	Srv.Handle("/api/user/role/{role_id:[a-fA-F0-9]+}/permission/add", app.ApiHandler(AddUserPermission)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/user/role/permission/{permission_id:[a-fA-F0-9]+}", app.ApiHandler(RemoveUserPermission)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/user/role/permission/{permission_id:[a-fA-F0-9]+}", app.ApiHandler(GetUserPermissionById)).Methods(http.MethodOptions, http.MethodGet)
}

func GetUserPermissionById(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetUserPermissionById"

	response := app.NewResultModel()
	// Get
	res := <-command.DataStore.AclStore().GetUserPermissionById(c.GetPathParam("permission_id"))
	response.FromResult(res)
	// result
	app.WriteResult(w, response)
}

func RemoveUserPermission(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "RemoveUserPermission"

	response := app.NewResultModel()
	// Remove user permission
	res := <-command.DataStore.AclStore().RemoveUserPermission(c.GetPathParam("permission_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddUserPermission(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddUserPermission"

	response := app.NewResultModel()
	// Add request
	var permission models.UserPermissions
	permission.Active = c.Data.GetBool("active")
	permission.PermissionName = c.Data.GetString("permission_name")
	res := <-command.DataStore.AclStore().AddUserPermission(c.GetPathParam("role_id"), permission)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func UserRolePermissions(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "UserRolePermissions"
	response := app.NewResultModel()
	// Get permissions
	res := <-command.DataStore.AclStore().GetUserRolePermissions(c.GetPathParam("role_id"), c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func DeleteUserRoleById(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "DeleteUserRoleById"

	response := app.NewResultModel()
	//Delete role by ID
	res := <-command.DataStore.AclStore().RemoveUserRole(c.GetPathParam("role_id"))
	response.FromResult(res)
	// Response
	app.WriteResult(w, response)

}

func GetUserRoleById(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetUserRoleById"

	response := app.NewResultModel()
	//Get role
	res := <-command.DataStore.AclStore().GetUserRoleById(c.GetPathParam("role_id"))
	response.FromResult(res)
	//result
	app.WriteResult(w, response)
}

func ListUserRoles(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListUserRoles"

	response := app.NewResultModel()
	// Get roles
	res := <-command.DataStore.AclStore().ListUserRoles(c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddUserRole(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddUserRole"

	response := app.NewResultModel()
	// Add user role
	var role models.UserRoles
	role.RoleName = c.Data.GetString("role_name")
	role.Active = c.Data.GetBool("active")
	role.Description = c.Data.GetString("description")
	res := <-command.DataStore.AclStore().AddUserRole(role)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}
