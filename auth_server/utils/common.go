package utils

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cesanta/glog"
	"io"
	"io/ioutil"
	"strings"
)

var NoMatch = errors.New("did not match any rule")
var WrongPass = errors.New("wrong password for user")

// Convert any struct into a json object
func ToJson(data interface{}) string {
	b, e := json.Marshal(data)
	if e != nil {
		fmt.Printf("hash failed: %v", e)
		return "{}"
	}
	return string(b)
}


// Convert any struct into a json object
func ToJsonPretty(data interface{}) string {
	b, e := json.MarshalIndent(data,"","\t")
	if e != nil {
		fmt.Printf("hash failed: %v", e)
		return "{}"
	}
	return string(b)
}

// Convert  json object to struct
func FromJson(jsonStr string, data interface{}) error {
	e := json.Unmarshal([]byte(jsonStr), data)
	if e != nil {
		return e
	}
	return nil
}

func ToStringMap(data interface{}) StringMap {
	if v, ok := data.(StringMap); ok {
		return v
	}
	dt := StringMap{}
	jsonStr := ToJson(data)
	err := FromJson(jsonStr, &dt)
	if err != nil {
		glog.V(2).Infof("Failed to convert to string map")
	}
	return dt
}

// Generate cryptographic random string
func RandomString(n int, extended bool) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return "", err
	}
	if extended {
		return base64.URLEncoding.EncodeToString(b), nil
	}
	return base32.StdEncoding.EncodeToString(b), nil

}
func ReadJson(closer io.ReadCloser, data interface{}) error {
	b, err := ioutil.ReadAll(closer)
	if err != nil {
		return err
	}
	err = json.Unmarshal(b, data)
	return err
}

// Copy-pasted from libtrust where it is private.
func Base64UrlEncode(b string) string {
	return JsonBase64UrlEncode([]byte(b))
}

// Copy-pasted from libtrust where it is private.
func JsonBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
