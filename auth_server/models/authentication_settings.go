package models

import "github.com/goonode/mogo"

const (
	MinLength           = "MinLength"
	HashingIterations   = "HashingIterations"
	MinSymbols          = 0
	MinNumbers          = 0
	LowerCaseCharacters = 0
	UpperCaseCharacters = 0
	AllowedSymbols      = ""
	RegularExpression   = ""
	ExpirePassword      = 0
	NotRecentlyUser     = 0
	PasswordBlackList   = "PasswordBlackList"
	OtpCharacterType    = "OtpCharacterType" // alpha, alphanumeric, numeric
	OtpHashingAlgorithm = "OtpHashingAlgorithm"
)

// Defines allowed extra fields on an application
type ExtraAttributeFields struct {
	mogo.DocumentModel `bson:",inline" collection:"cfg_model_extra_attributes"`
	FieldId            string `bson:"field_id" idx:"{field_id,app_context},unique"`
	ApplicationZone    string `bson:"app_context"`
	Description        string
}

// Authentication settings
type AuthenticationSetting struct {
	mogo.DocumentModel    `bson:",inline" collection:"cfg_authentication_settings"`
	RealmName             string `bson:"realm_name" idx:"{realm_name},unique"`
	RegistrationEnabled   bool
	LoginWithEmail        bool
	ForgotPasswordEnabled bool
	VerifyEmail           bool
	RememberMeEnabled     bool
	RequireSsl            bool // External authentication
}

// Password settings
type PasswordPolicy struct {
	mogo.DocumentModel `bson:",inline" collection:"cfg_password_policy"`
	PasswordType       string `bson:"password_type"` //opt or password
	PolicyKey          string `bson:"policy_key" idx:"{policy_key,password_type},unique"`
	PolicyValue        string
	Active             bool
	Description        string
}

// Password blacklist
type PasswordsBlackList struct {
	mogo.DocumentModel `bson:",inline" collection:"cfg_password_black_list"`
	Password           string `bson:"{password},unique"`
	Description        string
}

type AuthenticationProtocol struct {
	mogo.DocumentModel `bson:",inline" collection:"cfg_authentication_protocols"`
	ProtocolId         string `bson:"protocol_id" idx:"{protocol_id},unique"`
	Description        string
}
