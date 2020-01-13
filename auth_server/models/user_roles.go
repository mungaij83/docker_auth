package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

// Extra user permission attributes
type RoleAttributes struct {
	mogo.DocumentModel `bson:",inline" collection:"sys_user_permission_attributes"`
	AttrKey            string        `json:"attr_key"`
	AttrValue          string        `json:"attr_value"`
	PermissionRef      mogo.RefField `ref:"UserPermissions"`
}

// Defines the roles that a user has in an organization or system
type UserRoles struct {
	mogo.DocumentModel `bson:",inline" collection:"sys_user_roles"`
	RoleName           string `bson:"role_name" idx:"{role_name},unique"`
	Active             bool
	IsDefault          bool
	Description        string
	RoleAttributes     [] RoleAttributes
}

// Permissions defined under a role
type UserPermissions struct {
	mogo.DocumentModel `bson:",inline" collection:"sys_user_permissions"`
	PermissionName     string `bson:"permission_name" idx:"{permission_name,role_id},unique"`
	Active             bool
	RoleRef            bson.ObjectId `bson:"role_id" ref:"RealmRoles"`
}
