package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

const (
	PublicClient       = "public"
	ConfidentialClient = "confidential"
)

// Clients are entities that can request to authenticate a user
// Note:
// 1. confidential clients are only used with client credentials authorization
// 2. public clients can be used with SPA applications
type Clients struct {
	mogo.DocumentModel   `bson:",inline" collection:"dat_clients"`
	ClientName           string
	AppRealm             string // Application Realm
	ClientType           string // public or confidential
	ClientProtocol       string // openid, oauth2, basic_auth
	DynamicRedirect      bool
	RedirectUri          string
	BaseUri              string
	Description          string
	StandardFlowEnabled  bool
	ImplicitFlowEnabled  bool
	PasswordGrantEnabled bool
	AllowAllScope        bool
	Active               bool
	ClientId             string `bson:"client_id" idx:"{client_id},unique"`
	ClientSecret         string `json:"client_secret"`
	ClientSecret2        string `json:"-"`
}

// confidential clients may be part of a group
// Clients groups mappings
type ClientGroups struct {
	mogo.DocumentModel `bson:",inline" collection:"sys_client_groups"`
	ClientId           bson.ObjectId `bson:"client_id" ref:"Clients"`
	GroupId            bson.ObjectId `bson:"group_id" ref:"Groups"`
	Active             bool
	Description        string
}

// Client can have specific roles explicitly assigned
// Clients groups mappings
type ClientRealmRoles struct {
	mogo.DocumentModel `bson:",inline" collection:"sys_client_realm_roles"`
	ClientId           bson.ObjectId `bson:"client_id" ref:"Clients"`
	RoleId             bson.ObjectId `bson:"realm_role_id" ref:"RealmRoles"`
	Active             bool
	Description        string
}
