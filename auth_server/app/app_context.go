package app

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"net"
	"net/url"
)

type Context struct {
	IpAddress     string            `json:"ip_address"`
	Data          utils.StringMap   `json:"data"`
	FormData      url.Values        `json:"form_data"`
	Method        string            `json:"method"`
	MediaType     string            `json:"media_type"`
	PathParams    map[string]string `json:"path_params"`
	HeaderParams  url.Values        `json:"header_params"`
	HaveBasicAuth bool
}

func NewContext(ip string) *Context {
	return &Context{IpAddress: ip}
}

func (c Context) IsMultipart() bool {
	return c.MediaType == "multipart/form-data"
}
func (c Context) GetPathParam(name string) string {
	val, ok := c.PathParams[name]
	if ok {
		return val
	}
	return ""
}

func (c Context) GetUrlParam(name string) string {
	val := c.HeaderParams.Get(name)
	if val != "" {
		return val
	}
	return ""
}

// Parse IP address of the remote host
func (c Context) GetIp() net.IP {
	hp := hostPortRegex.FindStringSubmatch(c.IpAddress)
	ra := c.IpAddress
	if hp != nil {
		ra = string(hp[1])
	}
	res := net.ParseIP(ra)
	return res
}
