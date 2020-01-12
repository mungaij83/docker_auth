package models

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
	"time"
)

type Token struct {
	mogo.DocumentModel `bson:",inline" collection:"tmp_tokens"`
	TokenType          string    `json:"token_type,omitempty"` // Usually "Bearer"
	AccessToken        string    `bson:"access_token" json:"access_token,omitempty"`
	RefreshToken       string    `bson:"refresh_token" json:"refresh_token,omitempty"`
	SystemRealm        string    `bson:"system_realm" json:"system_realm"`
	ValidUntil         time.Time `json:"valid_until,omitempty"`
	LastAccess         time.Time
	Labels             utils.StringMap `json:"labels"`
	ClientId           bson.ObjectId   `ref:"Clients"`
	TokenValid         bool
}

func (t Token) ValidateExpiry() bool {
	tm := time.Now()
	return tm.After(t.ValidUntil)
}
