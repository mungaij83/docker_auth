package api

import (
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
	// Internal Users
	Srv.Handle("/api/user/register",app.ApiHandler(HandleRegisterUser))
}

func GetExternalUsers(c *app.Context, w http.ResponseWriter, r *http.Request) {
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

func HandleRegisterUser(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName="HandleRegisterUser"

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
	extUser := models.ExternalUsers{}
	extUser.Username = c.Data.GetString("username")
	extUser.Active = c.Data.GetBool("active")
	// Add user
	res := <-command.DataStore.Users().AddExternalUser(extUser)
	response := app.ResultModel{}
	response.FromResult(res)
	// Write result
	app.WriteResult(w, response)
}
