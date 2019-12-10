package app

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"html/template"
	"net/http"
)

type ResultModel struct {
	ResponseMessage string      `json:"response_message"`
	ResponseCode    string      `json:"response_code"`
	Data            interface{} `json:"data"`
}

func WriteResult(w http.ResponseWriter, data interface{}) {
	w.Header().Add("Content-Type", "Application/json")
	jsonData := utils.ToJson(data)
	count, err := w.Write([]byte(jsonData))
	if err != nil {
		glog.V(2).Infof("Failed to write result")
	} else {
		glog.V(2).Infof("Wrote %d bytes", count)
	}
}

func WriteTemplate(w http.ResponseWriter, data interface{}, templateName string){
	t, _ := template.ParseFiles(templateName)
	err := t.Execute(w, data)
	if err != nil {
		glog.V(3).Infof("Failed to load template: %v", err)
	}
}