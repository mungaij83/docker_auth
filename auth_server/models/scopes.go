package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type Scope struct {
	mogo.DocumentModel `bson:",inline" collection:"auth_service_scopes"`
	ScopeName          string `bson:"scope_name" idx:"{scope_name,service_Id},unique"`
	Active             bool
	Description        string
	ServiceId          bson.ObjectId `bson:"service_id"`
	RolesRefs          [] string
}
