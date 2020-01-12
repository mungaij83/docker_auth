package api

import (
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/gorilla/mux"
)

var Srv *mux.Router
var Auth *app.AuthService
var OAuth2 *app.Oauth2Auth

func NewApiRouter(c *utils.Config) error {
	Srv = mux.NewRouter()
	var err error
	err = command.InitCommand(c)
	if err != nil {
		return err
	}
	Auth, err = app.NewAuthService(c)
	if err != nil {
		return err
	}
	// Initialize Oauth 2
	OAuth2, err = app.NewOauth2(c, Auth)
	if err != nil {
		return err
	}
	InitAuth()
	InitAuth2()
	InitOpenId()
	// System APIs
	InitServiceApi()
	InitUserApi()
	InitClientApi()
	InitRealmRolesApi()
	InitUserRolesApi()
	InitGroupApi()
	InitSettingsApi()
	return nil
}
