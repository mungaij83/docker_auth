package app

import (
	"github.com/cesanta/docker_auth/auth_server/store"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"html/template"
	"net/http"
	"strconv"
)

type ResultModel struct {
	ResponseMessage string      `json:"response_message"`
	ResponseCode    string      `json:"response_code"`
	Data            interface{} `json:"data"`
}

func NewResultModel() ResultModel {
	return ResultModel{ResponseCode: strconv.FormatInt(http.StatusOK, 10)}
}

func (response *ResultModel) SetResponseCode(i int64) {
	response.ResponseCode = strconv.FormatInt(i, 10)
}

func (response *ResultModel) FromResult(res store.ResultStore) {
	response.Data = res.Data
	if res.Success {
		response.ResponseCode = strconv.FormatInt(http.StatusOK, 10)
		response.ResponseMessage = "Success"
	} else {
		if res.Error != nil {
			response.ResponseCode = strconv.FormatInt(http.StatusBadRequest, 10)
			response.ResponseMessage = res.Error.Error()
		} else {
			response.ResponseCode = strconv.FormatInt(http.StatusInternalServerError, 10)
			response.ResponseMessage = "request failed"
		}
	}
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

func WriteTemplate(w http.ResponseWriter, data interface{}, templateName string) {
	t, _ := template.ParseFiles(templateName)
	err := t.Execute(w, data)
	if err != nil {
		glog.V(3).Infof("Failed to load template: %v", err)
	}
}
