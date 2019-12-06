package utils

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var NoMatch = errors.New("did not match any rule")
var WrongPass = errors.New("wrong password for user")

// Convert any struct into a json object
func ToJson(data interface{}) string {
	b, e := json.Marshal(data)
	if e != nil {
		return "{}"
	}
	return string(b)
}

// Copy-pasted from libtrust where it is private.
func Base64UrlEncode(b string) string {
	return JsonBase64UrlEncode([]byte(b))
}

// Copy-pasted from libtrust where it is private.
func JsonBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
