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

// Authentication settings
type AuthenticationSetting struct {
	mogo.DocumentModel  `bson:",inline" coll:"user-coll"`
	RegistrationEnabled bool
	LoginWithEmail      bool
	ForgotPassword      bool
	VerifyEmail         bool
	RememberMeEnabled   bool
	RequireSsl          bool // External authentication
}

// Password settings
type PasswordPolicy struct {
	mogo.DocumentModel `bson:",inline" coll:"user-coll"`
	PolicyKey          string `bson:"{policy_key},unique"`
	PolicyValue        string
	PolicyValueType    string
}

// OTP token settings
type OtpPolicy struct {
	MinLength       int
	PolicyKey       string `bson:"{policy_key},unique"`
	PolicyValue     string
	PolicyValueType string
}

// Password blacklist
type PasswordsBlackList struct {
	mogo.DocumentModel `bson:",inline" coll:"user-coll"`
	Password           string `bson:"{password},unique"`
	Description        string
}
