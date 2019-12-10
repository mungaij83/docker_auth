package app

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"github.com/gorilla/mux"
	"net/http"
	"regexp"
	"strconv"
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
	//glog.V(3).Infof("Request: %+v", r)

	ctx := NewContext(r.RemoteAddr)
	ctx.PathParams = mux.Vars(r)
	ctx.HeaderParams = r.URL.Query()
	ctx.Method = r.Method
	// Process request body
	if h.AuthRequired {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		data, err := ParseRequestBody(r)
		if err != nil {
			glog.V(1).Infof("failed to parse body: %v", err)
			response := ResultModel{}
			response.ResponseCode = strconv.FormatInt(http.StatusUnprocessableEntity, 10)
			response.ResponseMessage = err.Error()
			WriteResult(w, response)
		} else {
			ctx.Data = data
			h.handlerFunc(ctx, w, r)
		}
	}

	glog.V(1).Infof("Processed request from %v", utils.ToJson(ctx))
}

func ParseRequestBody(r *http.Request) (utils.StringMap, error) {
	data := utils.StringMap{}
	if r.Method == http.MethodPost {
		err := utils.ReadJson(r.Body, &data)
		if err != nil {
			glog.Infof("Failed to read request data: %v", err)
			return data, err
		}
	} else {
		if err := r.ParseForm(); err != nil {
			glog.Infof("Failed to parse form data: %v", err)
		} else {
			for k, v := range r.Form {
				data.Add(k, v)
			}
		}
	}
	return data, nil
}
