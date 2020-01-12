package api

import (
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/api/forms"
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"net/http"
)

func InitGroupApi() {
	// Groups
	Srv.Handle("/api/groups", app.ApiHandler(ListGroups)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/group/add", app.ApiHandler(AddGroup)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/group/{group_id:[a-fA-F0-9]+}", app.ApiHandler(DeleteGroup)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/group/{group_id:[a-fA-F0-9]+}", app.ApiHandler(GetGroupById)).Methods(http.MethodOptions, http.MethodGet)
	// Group Attributes
	Srv.Handle("/api/group/{group_id:[a-fA-F0-9]+}/attr/add", app.ApiHandler(AddExtraGroupAttribute)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/group/{group_id:[a-fA-F0-9]+}/attr/{attr_id:[a-fA-F0-9]+}", app.ApiHandler(RemoveExtraGroupAttribute)).Methods(http.MethodOptions, http.MethodDelete)
	// Group user roles
	Srv.Handle("/api/group/{group_id:[a-fA-F0-9]+}/assign/role", app.ApiHandler(AssignRoleToGroup)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/group/{group_id:[a-fA-F0-9]+}/user/roles", app.ApiHandler(GetGroupUserRoles)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/group/{group_id:[a-fA-F0-9]+}/realm/roles", app.ApiHandler(GetGroupRealmRoles)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/group/{group_id:[a-fA-F0-9]+}/assign/user", app.ApiHandler(AssignUserToGroup)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/group/{group_id:[a-fA-F0-9]+}/assign/client", app.ApiHandler(AssignClientToGroup)).Methods(http.MethodOptions, http.MethodPost)

}

func AssignClientToGroup(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AssignClientToGroup"

	response := app.NewResultModel()
	// Decode
	var assignmentForm forms.ClientAssignmentForm
	err := c.Data.ToStruct(&assignmentForm)
	if err != nil {
		response.SetResponseCode(http.StatusUnprocessableEntity)
		response.ResponseMessage = "invalid request data"
		response.Data = c.Data
		app.WriteResult(w, response)
		return
	}
	// Assign
	res := <-command.DataStore.Groups().AddClient(assignmentForm.ClientId, c.GetPathParam("group_id"), assignmentForm.GetGroupAssignment())
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func GetGroupUserRoles(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetGroupUserRoles"

	response := app.NewResultModel()
	res := <-command.DataStore.Groups().GetGroupRoles(c.GetPathParam("group_id"), "user")
	response.FromResult(res)
	app.WriteResult(w, response)
}

func GetGroupRealmRoles(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetGroupRealmRoles"

	response := app.NewResultModel()
	res := <-command.DataStore.Groups().GetGroupRoles(c.GetPathParam("group_id"), "realm")
	response.FromResult(res)
	app.WriteResult(w, response)
}

func AssignUserToGroup(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AssignUserToGroup"

	response := app.NewResultModel()
	// Decode
	var assignmentForm forms.UserAssignmentForm
	err := c.Data.ToStruct(&assignmentForm)
	if err != nil {
		response.SetResponseCode(http.StatusUnprocessableEntity)
		response.ResponseMessage = "invalid request data"
		response.Data = c.Data
		app.WriteResult(w, response)
		return
	}
	// Groups
	res := <-command.DataStore.Groups().AddUser(assignmentForm.UserId, c.GetPathParam("group_id"), assignmentForm.GetGroupAssignment())
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AssignRoleToGroup(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AssignRoleToGroup"

	response := app.NewResultModel()
	var assignmentForm forms.RoleAssignmentForm
	err := c.Data.ToStruct(&assignmentForm)
	if err != nil {
		response.SetResponseCode(http.StatusUnprocessableEntity)
		response.ResponseMessage = "invalid request data"
		response.Data = c.Data
		app.WriteResult(w, response)
		return
	}
	groupId := c.GetPathParam("group_id")
	glog.V(1).Infof("Assign role to group:[%s]: %s ", groupId, utils.ToJson(assignmentForm))
	// Assign realm or user role to group
	switch assignmentForm.RoleType {
	case "user":
		res := <-command.DataStore.Groups().AssignUserRole(groupId, assignmentForm.RoleId, assignmentForm.GetGroupUserRole())
		response.FromResult(res)
		break
	case "realm":
		res := <-command.DataStore.Groups().AssignRealmRole(groupId, assignmentForm.RoleId, assignmentForm.GetGroupRealmRole())
		response.FromResult(res)
		break
	default:
		response.ResponseMessage = fmt.Sprintf("invalid role type: %s", assignmentForm.RoleType)
		response.SetResponseCode(http.StatusBadRequest)
	}
	app.WriteResult(w, response)
}

func RemoveExtraGroupAttribute(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "RemoveExtraGroupAttribute"

	response := app.NewResultModel()

	groupId := c.GetPathParam("group_id")
	attrId := c.GetPathParam("attr_id")
	res := <-command.DataStore.Groups().RemoveAttribute(attrId, groupId)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddExtraGroupAttribute(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddExtraGroupAttribute"

	response := app.NewResultModel()
	// Decode request
	var attributeForm forms.AttributeForm
	err := c.Data.ToStruct(&attributeForm)
	if err != nil {
		response.SetResponseCode(http.StatusUnprocessableEntity)
		response.ResponseMessage = "invalid request data"
		app.WriteResult(w, response)
		return
	}
	// Add attribute
	groupId := c.GetPathParam("group_id")
	res := <-command.DataStore.Groups().AddAttributeOrUpdate(groupId, attributeForm.GetGroupAttribute())
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func GetGroupById(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetGroupById"

	response := app.NewResultModel()
	res := <-command.DataStore.Groups().GetGroup(c.GetPathParam("group_id"))
	response.FromResult(res)
	//
	app.WriteResult(w, response)
}

func DeleteGroup(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "DeleteGroup"

	response := app.NewResultModel()
	//
	res := <-command.DataStore.Groups().RemoveGroup(c.GetPathParam("group_id"))
	response.FromResult(res)
	//
	app.WriteResult(w, response)
}

func AddGroup(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddGroup"
	response := app.NewResultModel()
	var groupForm forms.GroupForm
	err := c.Data.ToStruct(&groupForm)
	if err != nil {
		response.SetResponseCode(http.StatusUnprocessableEntity)
		response.ResponseMessage = "failed to decode data"
	} else {
		res := <-command.DataStore.Groups().AddGroup(groupForm.GetGroup())
		response.FromResult(res)
	}
	// Result
	app.WriteResult(w, response)
}

func ListGroups(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListGroups"

	response := app.NewResultModel()
	res := <-command.DataStore.Groups().ListGroups(c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}
