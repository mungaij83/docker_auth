package store

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type MongoSettingsStore struct {
	*MongoStore
}

func NewMongoSettingsStore(st *MongoStore) SettingsStore {
	mogo.ModelRegistry.Register(models.AuthenticationProtocol{}, models.ExtraAttributeFields{}, models.PasswordPolicy{}, models.AuthenticationSetting{}, models.PasswordsBlackList{})
	return MongoSettingsStore{st}
}

func (ss MongoSettingsStore) AddUpdateAuthenticationSettings(autSetting models.AuthenticationSetting) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if len(autSetting.RealmName) == 0 {
			autSetting.RealmName = "default"
		}
		authSettingsDoc := mogo.NewDoc(autSetting).(*models.AuthenticationSetting)
		p := mogo.NewDoc(models.AuthenticationSetting{}).(*models.AuthenticationSetting)
		err := authSettingsDoc.Find(bson.M{"realm_name": autSetting.RealmName}).One(p)
		if err == mgo.ErrNotFound {
			err = authSettingsDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = authSettingsDoc
			}
		} else if err != nil {
			result.Error = err
			result.Success = false
		} else {
			p.ForgotPasswordEnabled = autSetting.ForgotPasswordEnabled
			p.LoginWithEmail = autSetting.LoginWithEmail
			p.RememberMeEnabled = autSetting.RememberMeEnabled
			p.RequireSsl = autSetting.RequireSsl
			p.VerifyEmail = autSetting.VerifyEmail
			p.RegistrationEnabled = autSetting.RegistrationEnabled
			err = p.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = p
			}
		}
		st <- result
	}()
	return st
}

func (ss MongoSettingsStore) GetAuthenticationSetting(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		settings := make([]models.AuthenticationSetting, 0)
		authSettingsDoc := mogo.NewDoc(models.AuthenticationSetting{}).(*models.AuthenticationSetting)
		var err error
		err = authSettingsDoc.Find(bson.M{}).Limit(page.Size).Skip(page.Offset()).All(&settings)
		if err != nil {
			result.Error = err
			result.Success = false
			result.Data = settings
		} else {
			result.Data = settings
		}
		st <- result
	}()
	return st
}

func (ss MongoSettingsStore) RemoveAuthenticationSettings(authSettingId string) DataChannel {
	panic("implement me")
}

func (ss MongoSettingsStore) AddPasswordPolicy(policy models.PasswordPolicy) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()

		protocolDoc := mogo.NewDoc(policy).(*models.PasswordPolicy)
		p := mogo.NewDoc(models.PasswordPolicy{}).(*models.PasswordPolicy)
		err := protocolDoc.Find(bson.M{"policy_key": policy.PolicyKey, "password_type": policy.PasswordType}).One(p)
		if err == mgo.ErrNotFound {
			err = protocolDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = protocolDoc
			}
		} else if err != nil {
			result.Error = err
			result.Success = false
		} else {
			p.PolicyValue = policy.PolicyValue
			p.Description = policy.Description
			p.Active = policy.Active
			err = p.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = p
			}
		}
		st <- result
	}()
	return st
}

func (ss MongoSettingsStore) ListPasswordPolicies(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		policies := make([]models.PasswordPolicy, 0)
		passwordPolicyDoc := mogo.NewDoc(models.PasswordPolicy{}).(*models.PasswordPolicy)
		var err error
		err = passwordPolicyDoc.Find(bson.M{}).Limit(page.Size).Skip(page.Offset()).All(&policies)
		if err != nil {
			result.Error = err
			result.Success = false
			result.Data = policies
		} else {
			result.Data = policies
		}
		st <- result
	}()
	return st
}

func (ss MongoSettingsStore) RemovePasswordPolicy(policyId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(policyId) {
			result.Error = errors.New("invalid policy id")
			result.Success = false
			st <- result
			return
		}
		id := bson.ObjectIdHex(policyId)
		policyDoc := mogo.NewDoc(models.PasswordPolicy{}).(*models.PasswordPolicy)
		err := policyDoc.FindByID(id, policyDoc)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			err = policyDoc.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = policyDoc
			}
		}
		st <- result
	}()
	return st
}

func (ss MongoSettingsStore) AddExtraAttributeField(fld models.ExtraAttributeFields) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		attributesDoc := mogo.NewDoc(fld).(*models.ExtraAttributeFields)
		fields := mogo.NewDoc(models.ExtraAttributeFields{}).(*models.ExtraAttributeFields)
		err := attributesDoc.Find(bson.M{"field_id": fld.FieldId, "app_context": fld.ApplicationZone}).One(fields)
		if err == mgo.ErrNotFound {
			err = attributesDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = attributesDoc
			}
		} else if err != nil {
			result.Error = err
			result.Success = false
		} else {
			fields.Description = fld.Description
			err = fields.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = fields
			}
		}
		st <- result
	}()
	return st
}

func (ss MongoSettingsStore) ListExtraAttributeFields(applicationZone string, page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		protocols := make([]models.ExtraAttributeFields, 0)
		protocolDoc := mogo.NewDoc(models.ExtraAttributeFields{}).(*models.ExtraAttributeFields)
		var err error
		if len(applicationZone) > 0 {
			err = protocolDoc.Find(bson.M{"app_context": applicationZone}).Limit(page.Size).Skip(page.Offset()).All(&protocols)
		} else {
			err = protocolDoc.Find(bson.M{}).Limit(page.Size).Skip(page.Offset()).All(&protocols)
		}
		if err != nil {
			result.Error = err
			result.Success = false
			result.Data = protocols
		} else {
			result.Data = protocols
		}
		st <- result
	}()
	return st
}

func (ss MongoSettingsStore) RemoveExtraAttribute(attrId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(attrId) {
			result.Error = errors.New("invalid object id")
			result.Success = false
			st <- result
			return
		}
		id := bson.ObjectIdHex(attrId)
		protocolDoc := mogo.NewDoc(models.ExtraAttributeFields{}).(*models.ExtraAttributeFields)
		err := protocolDoc.FindByID(id, protocolDoc)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			err = protocolDoc.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = protocolDoc
			}
		}
		st <- result
	}()
	return st
}

// add or update protocol
func (ss MongoSettingsStore) AddAuthenticationProtocol(protocol models.AuthenticationProtocol) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		protocolDoc := mogo.NewDoc(protocol).(*models.AuthenticationProtocol)
		p := mogo.NewDoc(models.AuthenticationProtocol{}).(*models.AuthenticationProtocol)
		err := protocolDoc.Find(bson.M{"protocol_id": protocol.ProtocolId}).One(p)
		if err == mgo.ErrNotFound {
			err = protocolDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = protocolDoc
			}
		} else if err != nil {
			result.Error = err
			result.Success = false
		} else {
			p.Description = protocol.Description
			err = p.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = p
			}
		}
		st <- result
	}()
	return st
}

func (ss MongoSettingsStore) ListAuthenticationProtocol(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		protocols := make([]models.AuthenticationProtocol, 0)
		protocolDoc := mogo.NewDoc(models.AuthenticationProtocol{}).(*models.AuthenticationProtocol)
		err := protocolDoc.Find(bson.M{}).Limit(page.Size).Skip(page.Offset()).All(&protocols)
		if err != nil {
			result.Error = err
			result.Success = false
			result.Data = protocols
		} else {
			result.Data = protocols
		}
		st <- result
	}()
	return st
}

func (ss MongoSettingsStore) GetAuthenticationProtocol(protocolId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(protocolId) {
			result.Error = fmt.Errorf("invalid protocol identifier : %s", protocolId)
			result.Success = false
			st <- result
			return
		}
		id := bson.ObjectIdHex(protocolId)

		protocolDoc := mogo.NewDoc(models.AuthenticationProtocol{}).(*models.AuthenticationProtocol)
		err := protocolDoc.FindByID(id, protocolDoc)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = protocolDoc
		}
		st <- result
	}()
	return st
}
