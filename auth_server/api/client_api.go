package api

import (
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/command"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/glog"
	"net/http"
)

func InitClientApi() {
	Srv.Handle("/api/client/add", app.ApiHandler(HandleCreateClient)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/clients", app.ApiHandler(HandleListClient)).Methods(http.MethodOptions, http.MethodGet)
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}", app.ApiHandler(HandleDeleteClient)).Methods(http.MethodOptions, http.MethodDelete)
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}", app.ApiHandler(HandleGetOneClient)).Methods(http.MethodOptions, http.MethodGet)
	// Services
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}/service/add", app.ApiHandler(AddServiceToClient)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/client/{client_id:[A-Fa-f0-9]+}/services", app.ApiHandler(GetClientServices)).Methods(http.MethodOptions, http.MethodPost)
	Srv.Handle("/api/client/service/{client_service_id:[A-Fa-f0-9]+}", app.ApiHandler(DeleteClientServices)).Methods(http.MethodOptions, http.MethodDelete)
}

func DeleteClientServices(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName = "DeleteClientServices"

	response := app.NewResultModel()
	clientId := c.GetPathParam("client_service_id")
	res := <-command.DataStore.Clients().DeleteClientServices(clientId)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func GetClientServices(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName = "GetClientServices"

	response := app.NewResultModel()
	clientId := c.GetPathParam("client_id")
	res := <-command.DataStore.Clients().GetClientServices(clientId)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func AddServiceToClient(c *app.Context, w http.ResponseWriter, r *http.Request) {
	c.ActionName = "AddServiceToClient"

	response := app.NewResultModel()
	// Add service clients
	var clientService models.ClientServices
	clientService.Active = c.Data.GetBool("active")
	clientService.Description = c.Data.GetString("description")
	clientId := c.GetPathParam("client_id")
	serviceId := c.Data.GetString("service_id")
	glog.V(2).Infof("client[%v], service [%v]", clientId, serviceId)
	res := <-command.DataStore.Clients().AddService(serviceId, clientId, clientService)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func HandleGetOneClient(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleGetOneClient"

	response := app.NewResultModel()
	// Fetch clients
	res := <-command.DataStore.Clients().GetClientById(c.GetPathParam("client_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func HandleDeleteClient(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleDeleteClient"

	response := app.NewResultModel()
	// Fetch clients
	res := <-command.DataStore.Clients().RemoveClient(c.GetPathParam("client_id"))
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func HandleListClient(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleListClient"

	response := app.NewResultModel()
	// Fetch clients
	res := <-command.DataStore.Clients().ListClients(c.CurrentPage)
	response.FromResult(res)
	// Result
	app.WriteResult(w, response)
}

func HandleCreateClient(c *app.Context, w http.ResponseWriter, _ *http.Request) {
	c.ActionName = "HandleCreateClient"
	response := app.NewResultModel()
	var clientDetails models.Clients
	clientDetails.ClientName = c.Data.GetString("client_name")
	clientDetails.Active = c.Data.GetBool("active")
	clientDetails.Description = c.Data.GetString("description")
	clientDetails.DynamicRedirect = c.Data.GetBool("dynamic_redirect")
	clientDetails.RedirectUri = c.Data.GetString("redirect_uri")
	clientDetails.BaseUri = c.Data.GetString("base_uri")
	// Add client
	res := <-command.DataStore.Clients().AddClient(clientDetails)
	response.FromResult(res)
	// Write result
	app.WriteResult(w, response)
}
