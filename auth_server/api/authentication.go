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

func InitAuth() {
	Srv.Handle("/", app.ApiHandler(HandleIndex))
	Srv.Handle("/auth", app.ApiHandler(HandleAuth)).Methods(http.MethodOptions, http.MethodPost, http.MethodGet)
	Srv.Handle("/api/login", app.ApiHandler(LoginAdminUsers)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/google_auth", app.ApiHandler(GoogleAuthentication))
	Srv.Handle("/github_auth", app.ApiHandler(GithubAuthentication))
}

func LoginAdminUsers(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "LoginAdminUsers"
	response := app.NewResultModel()
	var loginForm forms.LoginForm
	err := c.Data.ToStruct(&loginForm)
	if err != nil {
		response.ResponseMessage = "Could not decode request"
		response.SetResponseCode(http.StatusUnprocessableEntity)
		app.WriteResult(w, response)
		return
	}
	// Authenticate user
	res := <-command.DataStore.Users().GetUserForLogin(loginForm.Username, loginForm.Password, "", true)
	if res.HasError() {
		response.ResponseMessage = res.Error.Error()
		response.SetResponseCode(http.StatusBadRequest)
		app.WriteResult(w, response)
		return
	}
	principal := res.Data.(utils.PrincipalDetails)
	// Add roles and generate token
	principal.Roles = command.DataStore.Users().GetUserRoles(principal.UserId, principal.RealmName, false)
	token, err := Auth.CreateToken(principal)
	if err != nil {
		response.ResponseMessage = err.Error()
		response.SetResponseCode(http.StatusBadRequest)
	} else {
		response.Data = token
	}

	app.WriteResult(w, response)

}

// Handle github authentication
func GithubAuthentication(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName = "GithubAuthentication"
	if Auth.GoogleAuthEnabled() {
		url := Auth.GetServerConfig().PathPrefix + "/github_auth"
		http.Redirect(w, r, url, 301)
	} else {
		_, _ = fmt.Fprintf(w, "<h1>Invalid request: %s</h1>\n", Auth.GetToken().Issuer)
	}
}

func GoogleAuthentication(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName = "GoogleAuthentication"
	if Auth.GithubAuthEnabled() {
		url := Auth.GetServerConfig().PathPrefix + "/github_auth"
		http.Redirect(w, r, url, 301)
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<h1>%s</h1>\n", Auth.GetToken().Issuer)
	}
}

func HandleAuth(c *app.Context, rw http.ResponseWriter, _ *http.Request) {
	ar, err := Auth.ParseRequest(c, c.GetIp())
	if err != nil {
		glog.Warningf("Bad request: %s", err)
		http.Error(rw, fmt.Sprintf("Bad request: %s", err), http.StatusBadRequest)
		return
	}
	glog.V(2).Infof("Auth request: %+v", ar)
	authnResult, principal, err := Auth.AuthenticateUser(ar)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Authentication failed (%s)", err), http.StatusInternalServerError)
		return
	}
	if !authnResult {
		glog.Warningf("Auth failed: %s", *ar)
		rw.Header()["WWW-Authenticate"] = []string{fmt.Sprintf(`Basic realm="%s"`, Auth.GetToken().Issuer)}
		http.Error(rw, "Auth failed.", http.StatusUnauthorized)
		return
	}

	token, err := Auth.CreateToken(*principal)
	if err != nil {
		msg := fmt.Sprintf("Failed to generate token %s", err)
		http.Error(rw, msg, http.StatusInternalServerError)
		glog.Errorf("%s: %s", ar, msg)
		return
	}
	// https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
	// describes that the response should have the token in `access_token`
	result := utils.ToJson(token)
	glog.V(3).Infof("%s", result)
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write([]byte(result))
}

// https://developers.google.com/identity/sign-in/web/server-side-flow
func HandleIndex(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleIndex"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<h1>%s</h1>\n", Auth.GetToken().Issuer)
}
