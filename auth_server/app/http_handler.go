package app

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"github.com/gorilla/mux"
	"mime"
	"net/http"
	"regexp"
	"strconv"
)

var (
	hostPortRegex = regexp.MustCompile(`\[?(.+?)]?:\d+$`)
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
	ctx := NewContext(r.RemoteAddr)
	ctx.PathParams = mux.Vars(r)
	ctx.HeaderParams = r.URL.Query()
	ctx.Method = r.Method
	// Parse content media
	err := ParseContentType(r, ctx)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		glog.Infof("Failed to parse request content: %v", err)
		response := ResultModel{}
		response.ResponseCode = strconv.FormatInt(http.StatusUnprocessableEntity, 10)
		response.ResponseMessage = err.Error()
		WriteResult(w, response)
		return
	}
	glog.V(1).Infof("Content Type: %s", ctx.MediaType)
	// Process request body
	if h.AuthRequired {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		data, err := ParseRequestBody(r, ctx)
		if err != nil {
			glog.V(1).Infof("failed to parse body: %v", err)
			response := ResultModel{}
			response.ResponseCode = strconv.FormatInt(http.StatusUnprocessableEntity, 10)
			response.ResponseMessage = err.Error()
			WriteResult(w, response)
		} else {
			ctx.Data = data
			// Handle server error gracefully
			//defer func() {
			//	if err := recover(); err != nil {
			//		glog.V(1).Infof("Error processing request from %v: %v", utils.ToJson(ctx), err)
			//		response := NewResultModel()
			//		response.ResponseMessage = "invalid request received"
			//		response.ResponseCode = strconv.FormatInt(http.StatusInternalServerError, 10)
			//		WriteResult(w, response)
			//	}
			//}()
			// Process request
			h.handlerFunc(ctx, w, r)
		}
	}

	glog.V(1).Infof("Processed request from %v", utils.ToJson(ctx))
}
func ParseContentType(r *http.Request, c *Context) error {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	mediatype, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return err
	}
	c.MediaType = mediatype
	return nil
}

func ParseRequestBody(r *http.Request, ctx *Context) (utils.StringMap, error) {
	data := utils.StringMap{}
	switch ctx.MediaType {
	case "application/json":
		if r.Method == http.MethodPost {
			err := utils.ReadJson(r.Body, &data)
			if err != nil {
				glog.Infof("Failed to read request data: %v", err)
			}
		}
		break
	case "multipart/form-data":
		// Parse request data
		if err := r.ParseForm(); err != nil {
			glog.Infof("Failed to parse form data: %v", err)
		} else {
			ctx.FormData = r.Form
		}
		break
	}
	user, password, haveBasicAuth := r.BasicAuth()
	if haveBasicAuth {
		ctx.HaveBasicAuth = haveBasicAuth
		data.Add("username", user)
		data.Add("password", password)
	}
	return data, nil
}
