package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type UserAttributes struct {
	mogo.DocumentModel `bson:",inline" collection:"crm_user_attributes"`
	AttrKey            string `json:"attr_key"`
	AttrValue          string `json:"attr_value"`
}

const (
	ExternalAccount = "external"
	InternalAccount = "internal"
)

// Base system users
type BaseUsers struct {
	mogo.DocumentModel `bson:",inline" collection:"adm_users"`
	Username           string            `idx:"{username,allowed_system_realm},unique"`
	Active             bool              `json:"active"`
	AccountType        string            `bson:"account_type" json:"account_type"` // external or internal
	HashedPassword     string            `json:"-"`
	AllowedSystemRealm string            `bson:"allowed_system_realm"` // Reference to system scopes
	ExtraAttributes    [] UserAttributes `json:"extra_attributes"`
}

// These are only for internal users
type Users struct {
	mogo.DocumentModel `bson:",inline" collection:"crm_admin_users"`
	Username           string `idx:"{username},unique"`
	FirstName          string
	MiddleName         string
	Surname            string
	EmailAddress       string `idx:"{email_address},unique"`
	PhoneNumber        string
	AltPhoneNumber     string
	Description        string
	UserId             bson.ObjectId `idx:"{user_id},unique" bson:"user_id" ref:"BaseUsers"`
}


