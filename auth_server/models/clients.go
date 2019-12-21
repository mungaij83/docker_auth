package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

// Clients are entities that can request to authenticate a user
type Clients struct {
	mogo.DocumentModel `bson:",inline" coll:"client-coll"`
	ClientName         string
	AppRealm           string // Application Realm
	ClientType         string // public or confidential
	DynamicRedirect    bool
	RedirectUri        string
	BaseUri            string
	Description        string
	Active             bool
	ClientId           string `idx:"{client_id},unique"`
	ClientSecret       string `json:"client_secret"`
	ClientSecret2      string `json:"-"`
}

// Clients groups mappings
type ClientGroups struct {
	mogo.DocumentModel `bson:",inline" coll:"client-services-coll"`
	ClientId           bson.ObjectId `bson:"client_id"`
	ClientRef          *Clients      `ref:"Clients"` // Required for internal auth
	GroupId            bson.ObjectId `bson:"group_id"`
	GroupRef           Groups        `ref:"Groups"`
	Active             bool
	Description        string
}

// Clients groups mappings
type ClientRealmRoles struct {
	mogo.DocumentModel `bson:",inline" coll:"client-services-coll"`
	ClientId           bson.ObjectId `bson:"client_id"`
	ClientRef          Clients       `ref:"Clients"` // Required for internal auth
	RoleId             bson.ObjectId `bson:"realm_role_id"`
	RoleRef            RealmRoles    `ref:"RealmRoles"`
	Active             bool
	Description        string
}
