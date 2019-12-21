package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

// Defines the roles that a user has in an organization or system
type UserRoles struct {
	mogo.DocumentModel `bson:",inline" coll:"role-coll"`
	RoleName           string
	Active             bool
	Description        string
}

// Permissions defined under a role
type UserPermissions struct {
	mogo.DocumentModel `bson:",inline" coll:"role-coll"`
	PermissionName     string
	Active             bool
	RoleId             bson.ObjectId
	RoleRef            UserRoles `ref:"RealmRoles"`
}

// Extra user permission attributes
type UserPermissionAttributes struct {
	mogo.DocumentModel
	AttrKey       string
	AttrValue     string
	PermissionId  bson.ObjectId
	PermissionRef UserPermissions `ref:"UserPermissions"`
}
