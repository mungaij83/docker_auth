package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type Scope struct {
	mogo.DocumentModel
	ScopeName   string `bson:"{scope_name},unique"`
	Active      bool
	Description string
}

// Extra scope attributes
type ScopeAttributes struct {
	mogo.DocumentModel
	AttrKey   string
	AttrValue string
	ScopeId   bson.ObjectId
	ScopeRef  Scope `ref:"Scope"`
}
