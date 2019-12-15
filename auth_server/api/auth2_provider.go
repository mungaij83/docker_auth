package api

import (
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func InitAuth2() {
	Srv.Handle("/login", app.ApiHandler(HandleLoginRequest))
	Srv.Handle("/auth/credentials/{realm:[A-Za-z0-9_]+}", app.ApiHandler(HandleClientCredentials))
	Srv.Handle("/auth/token/{realm:[A-Za-z0-9_]+}", app.ApiHandler(HandleToken))
	Srv.Handle("/validate/token/{realm:[A-Za-z0-9_]+}", app.ApiHandler(ValidateAccessToken))
}

func ValidateAccessToken(c *app.Context, w http.ResponseWriter, r *http.Request) {
	details := utils.TokenDetails{
		AccessToken:  c.Data.GetString("access_token"),
		RequestType:  "validate",
		RefreshToken: c.Data.GetString("refresh_token"),
		ServiceName:  c.GetPathParam("realm"),
	}
	// Validate access token  and send result
	data, err := OAuth2.ValidateAuthToken(details)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		app.WriteResult(w, data)
	}
}

// Validate response_code and generate access_code
func HandleToken(c *app.Context, w http.ResponseWriter, r *http.Request) {
	client := utils.AuthDetails{
		ClientId:          c.Data.GetString("client_id"),
		ClientSecret:      c.Data.GetString("client_secret"),
		Scope:             c.Data.GetString("scope"),
		ResponseType:      c.Data.GetString("response_type"),
		AuthorizationCode: c.Data.GetString("authorization_code"),
		Validation:        true,
	}
	errorList, ok := client.Validate()
	if ok {

		// Generate OAuth 2 token
		token, err := OAuth2.ValidateResponseCode(client)
		if err != nil {
			glog.Infof("Access token error: %v", err)
			response := app.ResultModel{}
			response.ResponseMessage = err.Error()
			response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
			app.WriteResult(w, response)
		} else {
			app.WriteResult(w, token)
		}
	} else {
		app.WriteResult(w, errorList)
	}

}

// Serve login page or validation failed page
func HandleLoginRequest(c *app.Context, w http.ResponseWriter, r *http.Request) {

	client := utils.AuthDetails{
		ClientId:     c.GetUrlParam("client_id"),
		Scope:        c.GetUrlParam("scope"),
		ResponseType: c.GetUrlParam("response_type"),
		Validation:   true,
	}
	errorList, ok := client.Validate()
	if ok {
		errorList = utils.StringMap{}
		ok, err := OAuth2.ValidateClientDetails(client)
		if err != nil {
			errorList.Add("error", err.Error())
			app.WriteTemplate(w, errorList, "templates/login_check_failed.html")
			return
		}

		if ok {
			app.WriteTemplate(w, nil, "templates/login.html")
		} else {
			errorList.Add("error", "Invalid client credentials")
			app.WriteTemplate(w, errorList, "templates/login_check_failed.html")
		}
	} else {
		app.WriteTemplate(w, errorList, "templates/login_check_failed.html")
	}
}

// Authorize client and generate authorization code
func HandleClientCredentials(c *app.Context, w http.ResponseWriter, r *http.Request) {
	ar, err := Auth.ParseRequest(c, c.GetIp())
	response := app.ResultModel{}
	if err != nil {
		glog.Warningf("Bad request: %s", err)
		response.ResponseMessage = fmt.Sprintf("Bad request: %s", err)
		response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
		http.Error(w, utils.ToJson(response), http.StatusBadRequest)
		return
	}
	glog.V(2).Infof("Request data: %v", utils.ToJson(c.Data))
	client := utils.AuthDetails{
		ClientId:     c.GetUrlParam("client_id"),
		ClientSecret: c.Data.GetString("client_secret"),
		Scope:        c.GetUrlParam("scope"),
		GrantType:    c.GetUrlParam("grant_type"),
		ResponseType: c.GetUrlParam("response_type"),
		RedirectUrl:  c.GetUrlParam("redirect_uri"),
		State:        c.GetUrlParam("state"),
		Validation:   true,
		Username:     ar.User,
		Password:     string(ar.Password),
	}
	errorList, ok := client.Validate()
	if !ok {
		glog.Warningf("Bad login: %v", err)
		response.Data = errorList
		response.ResponseMessage = fmt.Sprintf("Bad request: %v", err)
		response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
		w.WriteHeader(http.StatusBadRequest)
		app.WriteResult(w, response)
		return
	}
	// Get post login details
	if len(c.Data) > 0 {
		ar.Account = client.Username
		ar.Password = utils.PasswordString(client.Password)
	}
	ar.Service, _ = c.PathParams["realm"]
	_, err = OAuth2.ValidateAccount(ar.Account, ar.Password)
	if err != nil {
		glog.Warningf("Bad request: %s", err)
		response.ResponseMessage = fmt.Sprintf("Bad request: %s", err)
		response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
		http.Error(w, utils.ToJson(response), http.StatusBadRequest)
		return
	}
	// Generate authorization code
	if ok {
		code, redirect := GenerateToken(w, ar, client)
		if redirect {
			u, err := url.ParseRequestURI(client.RedirectUrl)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			} else {
				glog.V(2).Infof("Code: %s", code.GetString(utils.AuthorizationCodeField))
				u.Query().Add(utils.AuthorizationCodeField, code.GetString(utils.AuthorizationCodeField))
				http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
			}
		}
	} else {
		response.ResponseMessage = fmt.Sprintf("Invalid username or password: %s", err)
		response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
		http.Error(w, utils.ToJson(response), http.StatusBadRequest)
	}
}

func GenerateToken(w http.ResponseWriter, ar *utils.AuthRequest, client utils.AuthDetails) (code utils.StringMap, ok bool) {
	//Authenticated
	var err error
	ok = false
	ares := make([]utils.AuthzResult, 0)
	if len(ar.Scopes) > 0 {
		ares, err = Auth.Authorize(ar)
		if err != nil {
			http.Error(w, fmt.Sprintf("Authorization failed (%s)", err), http.StatusInternalServerError)
			return
		}
	}
	response := app.ResultModel{}
	// Grant token accordingly
	switch client.GrantType {
	case app.ClientCredentialsGrant:
		if strings.Compare(client.ResponseType, app.AuthorizationCodeGrantType) != 0 {
			response.ResponseMessage = fmt.Sprintf("invalid grant type: %s", client.ResponseType)
			response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
			app.WriteResult(w, response)
			return
		}
		// Generate token
		token, err := Auth.GrantClientCredentials(client, ar, ares)
		if err != nil {
			response.ResponseMessage = err.Error()
			response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
			app.WriteResult(w, response)
		} else {
			app.WriteResult(w, token)
		}
		break
	case app.ImplicitGrant:
		if strings.Compare(app.AccessTokenRequestType, client.ResponseType) != 0 {
			response.ResponseMessage = fmt.Sprintf("Invalid response type %s", client.ResponseType)
			response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
			app.WriteResult(w, response)
		} else {
			// No redirection required
			_, _ = GenerateAuthToken(w, ar, ares, client)
		}
		break
	case app.AuthorizationCodeGrantType:
		// Authorization and redirection enabled
		return GenerateAuthToken(w, ar, ares, client)
	case app.PasswordGrant:
		// Password grant
		if strings.Compare(app.AccessTokenRequestType, client.ResponseType) != 0 {
			response.ResponseMessage = fmt.Sprintf("Invalid response type %s", client.ResponseType)
			response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
			app.WriteResult(w, response)
		} else {
			// Generate client auth token
			client.ResponseType = app.PasswordRequestType
			_, _ = GenerateAuthToken(w, ar, ares, client)
		}
		break
	default:
		response.ResponseMessage = fmt.Sprintf("Invalid grant type %s", client.GrantType)
		response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
		app.WriteResult(w, response)
	}
	return
}
func GenerateAuthToken(w http.ResponseWriter, ar *utils.AuthRequest, ares []utils.AuthzResult, client utils.AuthDetails) (code utils.StringMap, ok bool) {
	// Generate grant code or token
	var err error
	switch client.ResponseType {
	case app.AccessTokenRequestType:
		token, err := Auth.CreateOAuthToken(ar, ares)
		if err != nil {
			msg := fmt.Sprintf("Failed to generate token %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			glog.Errorf("%s: %s", ar, msg)
			return
		}
		app.WriteResult(w, token)
		break
	case app.AuthorizationCodeRequestType:
		code, err = OAuth2.CreateAuthorizationCode(ar, ares)
		if err != nil {
			msg := fmt.Sprintf("Failed to generate token %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			glog.Errorf("%s: %s", ar, msg)
		} else {
			ok = true
		}
		break
	case app.PasswordRequestType:
		code, err = OAuth2.PasswordGrantToken(ar, ares, client)
		if err != nil {
			msg := fmt.Sprintf("Failed to generate token %s", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			glog.Errorf("%s: %s", ar, msg)
		} else {
			app.WriteResult(w, code)
		}
		break
	default:
		http.Error(w, fmt.Sprintf("Invalid request type: %v", client.ResponseType), http.StatusBadRequest)
	}
	return
}
