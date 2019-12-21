package models

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
	"time"
)

type Token struct {
	mogo.DocumentModel `bson:",inline" coll:"user-coll"`
	TokenType          string          `json:"token_type,omitempty"` // Usually "Bearer"
	AccessToken        string          `json:"access_token,omitempty"`
	RefreshToken       string          `json:"refresh_token,omitempty"`
	ValidUntil         time.Time       `json:"valid_until,omitempty"`
	Labels             utils.StringMap `json:"labels"`
	ClientId           bson.ObjectId
	ClientRef          *Clients `ref:"Clients"`
}
