package api

import (
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/glog"
	"net/http"
)

func InitSettingsApi() {
	// Authentication protocols
	Srv.Handle("/api/settings/auth/protocols", app.ApiHandler(ListAuthenticationProtocols)).Methods(http.MethodGet, http.MethodOptions)
	Srv.Handle("/api/settings/auth/protocol/{protocol_id:[a-fA-F0-9]+}", app.ApiHandler(GetAuthenticationProtocolById)).Methods(http.MethodGet, http.MethodOptions)
	// Manage extra attributes
	Srv.Handle("/api/settings/models/extra/attributes", app.ApiHandler(ListExtraAttributes)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/settings/models/extra/attribute", app.ApiHandler(AddApplicationExtraAttributes)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/settings/models/extra/attribute/{attr_id:[0-9a-fA-F]+}", app.ApiHandler(RemoveApplicationExtraAttribute)).Methods(http.MethodOptions, http.MethodDelete)
	// Password Policy
	Srv.Handle("/api/settings/password/policy", app.ApiHandler(AddPasswordPolicy)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/settings/password/policies", app.ApiHandler(ListPasswordPolicies)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/settings/password/policy/{policy_id:[a-fA-F0-9]+}", app.ApiHandler(DeletePasswordPolicy)).Methods(http.MethodOptions, http.MethodDelete)
	// Authentication settings
	Srv.Handle("/api/settings/auth/setting", app.ApiHandler(AddAuthenticationSettings)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/settings/auth/settings", app.ApiHandler(ListAuthenticationSettings)).Methods(http.MethodOptions, http.MethodGet)

}

func AddAuthenticationSettings(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddAuthenticationSettings"

	response := app.NewResultModel()
	// Authentication screen settings
	var authSetting models.AuthenticationSetting
	authSetting.RealmName = "default"
	authSetting.RegistrationEnabled = c.Data.GetBool("registration_enabled")
	authSetting.VerifyEmail = c.Data.GetBool("verify_email")
	authSetting.RequireSsl = c.Data.GetBool("require_ssl")
	authSetting.RememberMeEnabled = c.Data.GetBool("remember_me_enabled")
	authSetting.ForgotPasswordEnabled = c.Data.GetBool("forgot_password_enabled")
	res := <-command.DataStore.Settings().AddUpdateAuthenticationSettings(authSetting)
	response.FromResult(res)
	//Result
	app.WriteResult(w, response)
}
func ListAuthenticationSettings(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListAuthenticationSettings"

	response := app.NewResultModel()
	//
	res := <-command.DataStore.Settings().GetAuthenticationSetting(c.CurrentPage)
	response.FromResult(res)
	//Result
	app.WriteResult(w, response)
}

func DeletePasswordPolicy(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "DeletePasswordPolicy"

	response := app.NewResultModel()
	res := <-command.DataStore.Settings().RemovePasswordPolicy(c.GetPathParam("policy_id"))
	response.FromResult(res)
	app.WriteResult(w, response)
}

func ListPasswordPolicies(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListPasswordPolicies"

	response := app.NewResultModel()
	// Get policies
	res := <-command.DataStore.Settings().ListPasswordPolicies(c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddPasswordPolicy(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddPasswordPolicy"

	response := app.NewResultModel()
	// Policy details
	var policy models.PasswordPolicy
	policy.PolicyValue = c.Data.GetString("policy_value")
	policy.Active = c.Data.GetBool("active")
	policy.Description = c.Data.GetString("description")
	policy.PolicyKey = c.Data.GetString("policy_key")
	policy.PasswordType = c.Data.GetString("password_type")
	res := <-command.DataStore.Settings().AddPasswordPolicy(policy)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)

}

func RemoveApplicationExtraAttribute(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "RemoveApplicationExtraAttribute"

	response := app.NewResultModel()
	// Remove attribute
	res := <-command.DataStore.Settings().RemoveExtraAttribute(c.GetPathParam("attr_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddApplicationExtraAttributes(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "AddApplicationExtraAttributes"
	response := app.NewResultModel()
	// Add attribute or update description
	var extraFields models.ExtraAttributeFields
	extraFields.Description = c.Data.GetString("description")
	extraFields.FieldId = c.Data.GetString("field_id")
	extraFields.ApplicationZone = c.Data.GetString("app_context")
	res := <-command.DataStore.Settings().AddExtraAttributeField(extraFields)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func ListExtraAttributes(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListExtraAttributes"
	response := app.NewResultModel()
	// Extract context
	applicationContext := c.GetUrlParam("context")
	res := <-command.DataStore.Settings().ListExtraAttributeFields(applicationContext, c.CurrentPage)
	response.FromResult(res)
	// Results
	app.WriteResult(w, response)
}

func GetAuthenticationProtocolById(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "GetAuthenticationProtocolById"
	response := app.NewResultModel()
	//
	protocolId := c.GetPathParam("protocol_id")
	glog.Infof("find protocol by id: %v", protocolId)
	res := <-command.DataStore.Settings().GetAuthenticationProtocol(protocolId)
	response.FromResult(res)
	// Write result
	app.WriteResult(w, response)
}

func ListAuthenticationProtocols(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "ListAuthenticationProtocols"
	response := app.NewResultModel()
	// Get protocols
	res := <-command.DataStore.Settings().ListAuthenticationProtocol(c.CurrentPage)
	response.FromResult(res)
	// Write result
	app.WriteResult(w, response)
}
