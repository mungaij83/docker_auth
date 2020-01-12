package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

// Extra group attributes
type GroupAttributes struct {
	mogo.DocumentModel `bson:",inline" collection:"group_attributes"`
	AttrKey            string
	AttrValue          string
}

// Groups
type Groups struct {
	mogo.DocumentModel   `bson:",inline" collection:"groups"`
	GroupName            string `bson:"group_name" idx:"{group_name},unique"`
	Active               bool
	IsDefault            bool
	ExtraGroupAttributes [] GroupAttributes
	Description          string
}

// Map user roles ro a group
type GroupUserRoles struct {
	mogo.DocumentModel `bson:",inline" collection:"group_user_roles"`
	GroupId            bson.ObjectId `bson:"group_id" ref:"Groups" idx:"{group_id,user_role_id},unique"`
	UserRoleId         bson.ObjectId `bson:"user_role_id" ref:"UserRoles"`
	Active             bool
	Description        string
}

// Map realm roles to a group
type GroupRealmRoles struct {
	mogo.DocumentModel `bson:",inline" collection:"group_realm_roles"`
	GroupId            bson.ObjectId `bson:"group_id" ref:"Groups" idx:"{group_id,realm_role_id},unique"`
	RealmRoleId        bson.ObjectId `bson:"realm_role_id" ref:"RealmRoles"`
	Active             bool
	Description        string
}

// Users groups mappings
type UserGroups struct {
	mogo.DocumentModel `bson:",inline" collection:"crm_user_groups"`
	UserId             bson.ObjectId `bson:"user_id" ref:"BaseUsers"`
	GroupId            bson.ObjectId `bson:"group_id" ref:"Groups"`
	Active             bool
	Description        string
}
