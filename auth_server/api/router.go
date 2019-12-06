package api

import (
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/gorilla/mux"
)

var Srv *mux.Router
var Auth *app.AuthService

func NewApiRouter(c *utils.Config) error {
	Srv = mux.NewRouter()
	var err error
	Auth, err = app.NewAuthService(c)
	if err != nil {
		return err
	}
	InitAuth()
	return nil
}
