package models

import (
	"github.com/goonode/mogo"
)

// Authentication services
type AuthServices struct {
	mogo.DocumentModel `bson:",inline" collection:"cfg_services"`
	ServiceName        string `idx:"{service_name},unique"`
	AuthMethodTag      string
	Active             bool
	ServiceType        string
	Description        string
}

// System realms
type SystemRealms struct {
	mogo.DocumentModel `bson:",inline" collection:"sys_system_realms"`
	RealmName          string `bson:"realm_name" idx:"{realm_name},unique"`
	Active             bool
	IsDefault          bool `bson:"is_default"`
	Description        string
}
