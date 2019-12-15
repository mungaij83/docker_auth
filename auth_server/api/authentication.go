package api

import (
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/app"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"net/http"
)

func InitAuth() {
	Srv.Handle("/", app.ApiHandler(HandleIndex))
	Srv.Handle("/auth", app.ApiHandler(HandleAuth))
	Srv.Handle("/google_auth", app.ApiHandler(GoogleAuthentication))
	Srv.Handle("/github_auth", app.ApiHandler(GithubAuthentication))
}

// Handle github authentication
func GithubAuthentication(c *app.Context, w http.ResponseWriter, r *http.Request) {
	if Auth.GoogleAuthEnabled() {
		url := Auth.GetServerConfig().PathPrefix + "/github_auth"
		http.Redirect(w, r, url, 301)
	} else {
		_, _ = fmt.Fprintf(w, "<h1>Invalid request: %s</h1>\n", Auth.GetToken().Issuer)
	}
}

func GoogleAuthentication(c *app.Context, w http.ResponseWriter, r *http.Request) {
	if Auth.GithubAuthEnabled() {
		url := Auth.GetServerConfig().PathPrefix + "/github_auth"
		http.Redirect(w, r, url, 301)
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<h1>%s</h1>\n", Auth.GetToken().Issuer)
	}
}

func HandleAuth(c *app.Context, rw http.ResponseWriter, r *http.Request) {
	ar, err := Auth.ParseRequest(c, c.GetIp())
	ares := make([]utils.AuthzResult, 0)
	if err != nil {
		glog.Warningf("Bad request: %s", err)
		http.Error(rw, fmt.Sprintf("Bad request: %s", err), http.StatusBadRequest)
		return
	}
	glog.V(2).Infof("Auth request: %+v", ar)
	{
		authnResult, labels, err := Auth.Authenticate(ar)
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
		ar.Labels = labels
	}
	if len(ar.Scopes) > 0 {
		ares, err = Auth.Authorize(ar)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Authorization failed (%s)", err), http.StatusInternalServerError)
			return
		}
	} else {
		// Authentication-only request ("docker login"), pass through.
	}
	token, err := Auth.CreateToken(ar, ares)
	if err != nil {
		msg := fmt.Sprintf("Failed to generate token %s", err)
		http.Error(rw, msg, http.StatusInternalServerError)
		glog.Errorf("%s: %s", ar, msg)
		return
	}
	// https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
	// describes that the response should have the token in `access_token`
	result := utils.ToJson(&map[string]string{"access_token": token})
	glog.V(3).Infof("%s", result)
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write([]byte(result))
}

// https://developers.google.com/identity/sign-in/web/server-side-flow
func HandleIndex(c *app.Context, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<h1>%s</h1>\n", Auth.GetToken().Issuer)
}
