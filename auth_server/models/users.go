package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type Users struct {
	mogo.DocumentModel `bson:",inline" coll:"user-coll"`
	Username           string `idx:"{username},unique"`
	FirstName          string
	MiddleName         string
	Surname            string
	EmailAddress       string `idx:"{email_address},unique"`
	Password           string
	Salt               string
	Iterations         string
	Active             bool
	Description        string
}

type ExternalUsers struct {
	mogo.DocumentModel `bson:",inline" coll:"user-coll"`
	Username           string `idx:"{username},unique"`
	Active             bool
}

// External users groups mappings
type ExtUserGroups struct {
	mogo.DocumentModel `bson:",inline" coll:"client-services-coll"`
	UserId             bson.ObjectId `bson:"user_id"`
	UserRef            ExternalUsers `ref:"ExternalUsers"` // Required for internal auth
	GroupId            bson.ObjectId `bson:"group_id"`
	GroupRef           Groups        `ref:"Groups"`
	Active             bool
	Description        string
}

// Define extra user attributes
// These are only for internal users
type UserAttributes struct {
	mogo.DocumentModel `bson:",inline" coll:"user-coll"`
	AttrKey            string
	AttrValue          string
	UserId             bson.ObjectId
	UserRef            Users `ref:"Users"`
}

// Users groups mappings
type UserGroups struct {
	mogo.DocumentModel `bson:",inline" coll:"client-services-coll"`
	UserId             bson.ObjectId `bson:"user_id"`
	UserRef            Users         `ref:"Users"` // Required for internal auth
	GroupId            bson.ObjectId `bson:"group_id"`
	GroupRef           Groups        `ref:"Groups"`
	Active             bool
	Description        string
}
