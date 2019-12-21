package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

// Groups
type Groups struct {
	mogo.DocumentModel
	GroupName   string `bson:"{group_name},unique"`
	Active      bool
	Description string
}

// Extra group attributes
type GroupAttributes struct {
	mogo.DocumentModel
	AttrKey   string
	AttrValue string
}

// Map user roles ro a group
type GroupUserRoles struct {
	mogo.DocumentModel
	GroupId    bson.ObjectId
	UserRoleId bson.ObjectId
	RoleRef    UserRoles `ref:"UserRoles"`
}

// Map realm roles to a group
type GroupRealmRoles struct {
	mogo.DocumentModel
	GroupId     bson.ObjectId
	RealmRoleId bson.ObjectId
	RoleRef     RealmRoles `ref:"RealmRoles"`
}
