package models

import (
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

// Customer details
type Customers struct {
	mogo.DocumentModel `bson:",inline" collection:"crm_customers"`
	FirstName          string
	MiddleName         string
	Surname            string
	EmailAddress       string `idx:"{email_address},unique"`
	PhoneNumber        string `idx:"{phone_number},unique"`
	Description        string
	UserId             bson.ObjectId `idx:",unique" ref:"BaseUsers"`
}
