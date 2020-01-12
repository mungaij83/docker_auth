package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

// Defines the roles that a user has in an organization or system
type RealmRoles struct {
	mogo.DocumentModel `bson:",inline" collection:"ext_realm_roles"`
	RoleName           string `idx:"{role_name},unique"`
	Active             bool
	IsDefault          bool
	Description        string
	RoleAttributes     [] RoleAttributes
}

// RealmPermissions defined under a role
type RealmPermissions struct {
	mogo.DocumentModel `bson:",inline" collection:"ext_realm_role_permissions"`
	PermissionName     string `idx:"{permission_name},unique"`
	Active             bool
	RoleId             bson.ObjectId `bson:"role_id" ref:"RealmRoles"`
	Description        string
}
