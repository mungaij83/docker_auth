package store

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
	"strings"
)

type MongoUserStore struct {
	*MongoStore
}

func NewMongoUserStore(st *MongoStore) UserStore {
	usr := MongoUserStore{st}
	mogo.ModelRegistry.Register(models.Users{}, models.BaseUsers{}, models.UserAttributes{})
	return usr
}

func (us MongoUserStore) GetExternalUser(userId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Check valid id
		if !bson.IsObjectIdHex(userId) {
			result.Error = errors.New("invalid user id")
			result.Success = false
			st <- result
			return
		}
		id := bson.ObjectIdHex(userId)
		// Find document
		existDoc := mogo.NewDoc(models.BaseUsers{}).(*models.BaseUsers)
		err := existDoc.FindID(id).One(existDoc)
		if err != nil {
			glog.V(2).Infof("Failed to get user[%v]: %v", id, err)
			result.Error = err
			result.Success = false
		} else {
			result.Data = existDoc
		}
		st <- result
	}()
	return st
}
func (us MongoUserStore) GetUserRoles(userId string, realm string, isUsername bool) []utils.AuthzResult {
	roles := make([]utils.AuthzResult, 0)
	if isUsername {
		docs := mogo.NewDoc(models.BaseUsers{}).(*models.BaseUsers)
		err := docs.Find(bson.M{"username": userId, "allowed_system_realm": realm}).One(docs)
		if err != nil {
			glog.V(2).Infof("invalid user account: %v", err)
			return roles
		} else {
			userId = docs.ID.Hex()
		}
	}
	res := <-us.Groups().GetUserRoles(userId)
	if res.HasError() {
		return roles
	}
	data, ok := res.Data.([]utils.StringMap)
	if !ok {
		return roles
	}

	return us.ParseRoles(data, false)
}
func (us MongoUserStore) ListExternalUsers(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		var users [] models.BaseUsers
		docs := mogo.NewDoc(models.BaseUsers{}).(*models.BaseUsers)
		err := docs.Find(bson.M{"account_type": models.ExternalAccount}).Skip(page.Offset()).Limit(page.Size).All(&users)
		if err != nil {
			result.Error = err
		} else {
			result.Data = users
		}
		st <- result
	}()
	return st
}

// Find user and validate their password
func (us MongoUserStore) GetUserForLogin(username, password, realm string, defaultAllowed bool) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		var err error
		var defaultRealm *models.SystemRealms
		if defaultAllowed {
			defaultRealm, err = us.Services().GetDefaultSystemRealm()
			if err != nil {
				result.Error = err
				result.Success = false
				st <- result
				return
			}
		}
		// Find account within the default realm or account realm
		q := bson.M{"username": username}
		if defaultAllowed {
			q["allowed_system_realm"] = bson.M{"$in": []string{defaultRealm.RealmName, realm}}
		} else {
			q["allowed_system_realm"] = realm
		}

		userDocs := mogo.NewDoc(models.BaseUsers{}).(*models.BaseUsers)
		err = userDocs.Find(q).One(userDocs)
		// User not found
		if err != nil {
			glog.V(2).Infof("user details not found[%+v]: %v", q, err)
			result.Error = fmt.Errorf("invalid username or password")
			result.Success = false
		} else if strings.Compare(userDocs.AccountType, models.ExternalAccount) == 0 {
			glog.V(2).Infof("external account[%v] cannot login", username)
			result.Error = fmt.Errorf("invalid username or password")
			result.Success = false
		} else {
			// Validate user password
			h, _ := utils.NewHashParameters(true, utils.Pbkdf2Sha512, userDocs.HashedPassword)
			if h.ValidateHash(password) {
				var userDetails utils.PrincipalDetails
				userDetails.Username = username
				userDetails.Active = userDocs.Active
				userDetails.RealmName = userDocs.AllowedSystemRealm
				userDetails.Roles = make([]utils.AuthzResult, 0)
				result.Data = userDetails
			} else {
				result.Error = fmt.Errorf("invalid username or password")
				result.Success = false
			}
		}
		st <- result
	}()
	return st
}

// Add external user to list of external users
func (us MongoUserStore) AddExternalUser(user models.BaseUsers) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		realmDoc := mogo.NewDoc(models.SystemRealms{}).(*models.SystemRealms)
		opts := make([]bson.M, 0)
		if len(user.AllowedSystemRealm) > 0 {
			opts = append(opts, bson.M{"realm_name": user.AllowedSystemRealm})
			opts = append(opts, bson.M{"RealmName": user.AllowedSystemRealm})
		} else {
			opts = append(opts, bson.M{"is_default": true})
			opts = append(opts, bson.M{"realm_name": "default"})
			opts = append(opts, bson.M{"RealmName": "default"})
		}
		err := realmDoc.Find(bson.M{"$or": opts}).One(realmDoc)
		if err != nil {
			result.Error = fmt.Errorf("invalid realm name[%s]: %v", user.AllowedSystemRealm, err)
			result.Success = false
			st <- result
			return
		}
		// Override
		if realmDoc.IsDefault {
			user.AllowedSystemRealm = realmDoc.RealmName
		}
		// Validate use not exist
		existDoc := mogo.NewDoc(models.BaseUsers{}).(*models.BaseUsers)
		dd := models.BaseUsers{}
		err = existDoc.Find(bson.M{"username": user.Username, "allowed_system_realm": user.AllowedSystemRealm}).One(&dd)
		// Add use if no user with username in realm
		if err == mgo.ErrNotFound {
			doc := mogo.NewDoc(user).(*models.BaseUsers)
			doc.AccountType = models.ExternalAccount

			err := doc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = doc
			}
		} else {
			glog.V(1).Infof("user exists: %v", err)
			result.Error = errors.New("user with username already exists")
			result.Success = false
		}
		st <- result
	}()
	return st
}

func (us MongoUserStore) GetUserById(userId string) (*models.BaseUsers, error) {
	// Check valid id
	if !bson.IsObjectIdHex(userId) {
		return nil, errors.New("invalid user id")
	}
	id := bson.ObjectIdHex(userId)
	// Find document
	existDoc := mogo.NewDoc(models.BaseUsers{}).(*models.BaseUsers)
	err := existDoc.FindID(id).One(existDoc)

	return existDoc, err
}
func (us MongoUserStore) RemoveExternalUser(userId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Check valid id
		if !bson.IsObjectIdHex(userId) {
			result.Error = errors.New("invalid user id")
			result.Success = false
			st <- result
			return
		}
		id := bson.ObjectIdHex(userId)
		// Find document
		existDoc := mogo.NewDoc(models.BaseUsers{}).(*models.BaseUsers)
		err := existDoc.FindID(id).One(existDoc)
		if err != nil {
			glog.V(2).Infof("Failed to get object[%v]: %v", id, err)
			result.Error = err
			result.Success = false
		} else {
			// Remove document
			err = existDoc.Remove()
			if err != nil {
				glog.V(2).Infof("Failed to delete object[%v]: %v", id, err)
				result.Error = err
				result.Success = false
			} else {
				result.Data = existDoc
			}
		}
		st <- result
	}()
	return st
}

func (us MongoUserStore) AddUserExtraAttribute(userId string, attribute models.UserAttributes) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Check valid id
		if !bson.IsObjectIdHex(userId) {
			result.Error = errors.New("invalid user id")
			result.Success = false
			st <- result
			return
		}

		existDoc := mogo.NewDoc(models.BaseUsers{}).(*models.BaseUsers)
		err := existDoc.FindID(bson.ObjectIdHex(userId)).One(existDoc)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			if len(existDoc.ExtraAttributes) == 0 {
				existDoc.ExtraAttributes = make([]models.UserAttributes, 0)
			}
			// Check attribute exists
			attributeExits := -1
			for idx, i := range existDoc.ExtraAttributes {
				if i.AttrKey == attribute.AttrKey {
					attributeExits = idx
					break
				}
			}
			if attributeExits >= 0 {
				existDoc.ExtraAttributes[attributeExits].AttrValue = attribute.AttrValue
				err = existDoc.Save()
				if err != nil {
					result.Error = err
					result.Success = false
				} else {
					result.Data = existDoc
				}
			} else {
				mn := mogo.NewDoc(attribute).(*models.UserAttributes)
				mn.ID = bson.NewObjectId()

				existDoc.ExtraAttributes = append(existDoc.ExtraAttributes, *mn)
				err = existDoc.Save()
				if err != nil {
					result.Error = err
					result.Success = false
				} else {
					result.Data = existDoc
				}
			}
		}
		st <- result
	}()
	return st
}

func (us MongoUserStore) RemoveUserExtraAttribute(userId string, attributeId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Check valid id
		if !bson.IsObjectIdHex(userId) {
			result.Error = errors.New("invalid user id")
			result.Success = false
			st <- result
			return
		}
		// Attributes id is valid
		if !bson.IsObjectIdHex(attributeId) {
			result.Error = errors.New("invalid attribute id")
			result.Success = false
			st <- result
			return
		}

		existDoc := mogo.NewDoc(models.BaseUsers{}).(*models.BaseUsers)
		err := existDoc.FindID(bson.ObjectIdHex(userId)).One(existDoc)
		if err != nil {
			result.Error = err
			result.Success = false
		} else if len(existDoc.ExtraAttributes) == 0 {
			result.Error = errors.New("attribute not found")
			result.Success = false
		} else {
			// Check attribute exists
			attributeExits := -1
			for idx, i := range existDoc.ExtraAttributes {
				if i.ID == bson.ObjectIdHex(attributeId) {
					attributeExits = idx
					// Remove item at location from slice
					existDoc.ExtraAttributes = append(existDoc.ExtraAttributes[:idx], existDoc.ExtraAttributes[idx+1:]...)
					break
				}
			}
			// show new record
			if attributeExits >= 0 {
				err = existDoc.Save()
				if err != nil {
					result.Error = err
					result.Success = false
				} else {
					result.Data = existDoc
				}
			} else {
				result.Error = errors.New("invalid attribute id")
				result.Success = false
			}
		}
		st <- result
	}()
	return st
}

func (us MongoUserStore) AddUser(user models.Users) DataChannel {
	panic("implement me")
}

func (us MongoUserStore) UpdateUser(id string, user models.Users) DataChannel {
	panic("implement me")
}

func (us MongoUserStore) RemoveUser(id string) DataChannel {
	panic("implement me")
}

func (us MongoUserStore) ListUsers(page Page) DataChannel {
	panic("implement me")
}
