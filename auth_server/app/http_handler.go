package app

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"github.com/gorilla/mux"
	"net/http"
	"regexp"
)

var (
	hostPortRegex = regexp.MustCompile(`\[?(.+?)\]?:\d+$`)
)

type RequestHandlerFunc func(c *Context, w http.ResponseWriter, r *http.Request)

type RequestHandler struct {
	handlerFunc  RequestHandlerFunc
	AuthRequired bool
}

// ApiHandler
func ApiHandler(fn RequestHandlerFunc) RequestHandler {
	return RequestHandler{
		handlerFunc:  fn,
		AuthRequired: false,
	}
}

func (h RequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	glog.V(3).Infof("Request: %+v", r)

	ctx := NewContext(r.RemoteAddr)
	ctx.PathParams = mux.Vars(r)
	ctx.HeaderParams = r.URL.Query()
	ctx.Method = r.Method
	if h.AuthRequired {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		h.handlerFunc(ctx, w, r)
	}
	glog.V(1).Infof("Processed request from %v", utils.ToJson(ctx))
}
