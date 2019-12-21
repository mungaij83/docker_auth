package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

// Defines the roles that a user has in an organization or system
type RealmRoles struct {
	mogo.DocumentModel `bson:",inline" coll:"role-coll"`
	RoleName           string
	Active             bool
	Description        string
}

// RealmPermissions defined under a role
type RealmPermissions struct {
	mogo.DocumentModel `bson:",inline" coll:"role-coll"`
	PermissionName     string
	Active             bool
	RoleId             bson.ObjectId
	RoleRef            RealmRoles `ref:"RealmRoles"`
}

// Extra realm permission attributes
type RealmPermissionAttributes struct {
	mogo.DocumentModel
	AttrKey       string
	AttrValue     string
	PermissionId  bson.ObjectId
	PermissionRef RealmPermissions `ref:"RealmPermissions"`
}
