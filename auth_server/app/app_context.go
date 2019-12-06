package app

import (
	"net"
	"net/url"
)

type Context struct {
	IpAddress    string            `json:"ip_address"`
	Data         interface{}       `json:"data"`
	Method       string            `json:"method"`
	PathParams   map[string]string `json:"path_params"`
	HeaderParams url.Values        `json:"header_params"`
}

func NewContext(ip string) *Context {
	return &Context{IpAddress: ip}
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
