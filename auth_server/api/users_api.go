package api

import (
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/glog"
	"net/http"
)

func InitUserApi() {
	// External users
	Srv.Handle("/api/add/user", app.ApiHandler(HandleAddUser)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/ext/users", app.ApiHandler(HandleListExternalUsers)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/ext/user/{user_id:[a-fA-F0-9]+}", app.ApiHandler(DeleteExternalUsers)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/ext/user/{user_id:[a-fA-F0-9]+}", app.ApiHandler(GetExternalUsers)).Methods(http.MethodOptions, http.MethodGet)
	// Add extra properties
	Srv.Handle("/api/user/{user_id:[a-fA-F0-9]+}/extra", app.ApiHandler(AddUserExtraAttributes)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/user/{user_id:[a-fA-F0-9]+}/extra/{extra_id:[a-fA-F0-9]+}", app.ApiHandler(RemoveUserExtraAttribute)).Methods(http.MethodOptions, http.MethodPost)
	// Internal Users
	Srv.Handle("/api/user/register", app.ApiHandler(HandleRegisterUser))
	// Roles and groups
	Srv.Handle("/api/user/{user_id:[a-fA-F0-9]+}/roles", app.ApiHandler(GetUserAssignRoles)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/user/{user_id:[a-fA-F0-9]+}/groups", app.ApiHandler(GetUserAssignedGroups)).Methods(http.MethodOptions, http.MethodGet)

}

func GetUserAssignedGroups(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetUserAssignedGroups"

	response := app.NewResultModel()
	// Get user groups
	res := <-command.DataStore.Groups().GetUserGroups(c.GetPathParam("user_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func GetUserAssignRoles(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetUserAssignRoles"

	response := app.NewResultModel()
	// Get user roles
	res := <-command.DataStore.Groups().GetUserRoles(c.GetPathParam("user_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func RemoveUserExtraAttribute(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "RemoveUserExtraAttribute"

	response := app.NewResultModel()
	res := <-command.DataStore.Users().RemoveUserExtraAttribute(c.GetPathParam("user_id"), c.GetPathParam("extra_id"))
	response.FromResult(res)

	app.WriteResult(w, response)
}

func AddUserExtraAttributes(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddUserExtraAttributes"

	response := app.NewResultModel()
	// add attribute
	var attr models.UserAttributes
	attr.AttrKey = c.Data.GetString("attr_key")
	attr.AttrValue = c.Data.GetString("attr_value")
	res := <-command.DataStore.Users().AddUserExtraAttribute(c.GetPathParam("user_id"), attr)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func GetExternalUsers(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "DeleteExternalUsers"
	response := app.ResultModel{}
	userId := c.GetPathParam("user_id")
	glog.V(1).Infof("Delete user id: %s", userId)
	// Find user
	res := <-command.DataStore.Users().GetExternalUser(userId)
	response.FromResult(res)
	// Response
	app.WriteResult(w, response)
}

func HandleRegisterUser(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleRegisterUser"
	response := app.NewResultModel()
	response.ResponseCode = fmt.Sprintf("%d", http.StatusNotFound)
	app.WriteResult(w, response)

}

func DeleteExternalUsers(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "DeleteExternalUsers"
	response := app.ResultModel{}
	userId := c.GetPathParam("user_id")
	glog.V(1).Infof("Delete user id: %s", userId)
	// Delete user
	res := <-command.DataStore.Users().RemoveExternalUser(userId)
	response.FromResult(res)
	// Response
	app.WriteResult(w, response)
}

func HandleListExternalUsers(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleListExternalUsers"
	response := app.ResultModel{}
	// Get users
	res := <-command.DataStore.Users().ListExternalUsers(c.CurrentPage)
	response.FromResult(res)
	// result
	app.WriteResult(w, response)
}

func HandleAddUser(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleAddUser"
	extUser := models.BaseUsers{}
	extUser.Username = c.Data.GetString("username")
	extUser.Active = c.Data.GetBool("active")
	extUser.AccountType = models.ExternalAccount
	extUser.AllowedSystemRealm = c.Data.GetString("realm")
	// Add user
	res := <-command.DataStore.Users().AddExternalUser(extUser)
	response := app.ResultModel{}
	response.FromResult(res)
	// Write result
	app.WriteResult(w, response)
}
