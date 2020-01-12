package store

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/goonode/mogo"
)

type MongoServiceAclStore struct {
	*MongoStore
}

// Init service store
func NewMongoServiceAclStore(st *MongoStore) ServiceAclStore {
	acl := MongoServiceAclStore{st}
	mogo.ModelRegistry.Register(models.RealmRoles{}, models.RealmPermissions{}, models.ClientRealmRoles{}, models.UserRoles{}, models.UserPermissions{})
	return acl
}

func (sas MongoServiceAclStore) AssignUserRole(userId, roleId string) DataChannel {
	panic("implement me")
}

func (sas MongoServiceAclStore) RemoveAssignedUserRole(assignmentId string) DataChannel {
	panic("implement me")
}

func (sas MongoServiceAclStore) ListRealmRoles(page Page) DataChannel {
	st := make(DataChannel)

	go func() {
		result := NewResultStore()
		roles := make([]models.RealmRoles, 0)
		roleDocs := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
		err := roleDocs.Find(bson.M{}).Skip(page.Offset()).Limit(page.Size).All(&roles)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = roles
		}
		st <- result
	}()

	return st
}

func (sas MongoServiceAclStore) RealmRoleById(roleId string) (*models.RealmRoles, error) {
	if !bson.IsObjectIdHex(roleId) {
		return nil, errors.New("invalid role identifier")
	}
	rolesDoc := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
	err := rolesDoc.FindByID(bson.ObjectIdHex(roleId), rolesDoc)
	return rolesDoc, err
}

func (sas MongoServiceAclStore) UserRoleById(roleId string) (*models.UserRoles, error) {
	if !bson.IsObjectIdHex(roleId) {
		return nil, errors.New("invalid role identifier")
	}
	rolesDoc := mogo.NewDoc(models.UserRoles{}).(*models.UserRoles)
	err := rolesDoc.FindByID(bson.ObjectIdHex(roleId), rolesDoc)
	return rolesDoc, err
}

func (sas MongoServiceAclStore) AddRealmPermission(roleId string, realmPermissions models.RealmPermissions) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(roleId) {
			result.Error = errors.New("invalid role identifier")
			result.Success = false
			st <- result
			return
		}
		rolesDoc := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
		err := rolesDoc.FindByID(bson.ObjectIdHex(roleId), rolesDoc)
		if err != nil {
			result.Error = errors.New("realm role not found")
			result.Success = false
		} else {
			permissionDoc := mogo.NewDoc(realmPermissions).(*models.RealmPermissions)
			permissionDoc.RoleId = rolesDoc.ID
			err := permissionDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = permissionDoc
			}
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) UpdateRealmPermission(permissionId string, servRole models.RealmPermissions) DataChannel {
	panic("implement me")
}

func (sas MongoServiceAclStore) AddUserRole(usrRole models.UserRoles) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		roleDoc := mogo.NewDoc(usrRole).(*models.UserRoles)

		err := roleDoc.Find(bson.M{"role_name": usrRole.RoleName}).One(&models.UserRoles{})
		if err == mgo.ErrNotFound {
			err := roleDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = roleDoc
			}
		} else {
			result.Error = errors.New("role with name already exists")
			result.Success = false
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) ListUserRoles(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		roles := make([]models.UserRoles, 0)
		roleDocs := mogo.NewDoc(models.UserRoles{}).(*models.UserRoles)
		err := roleDocs.Find(bson.M{}).Skip(page.Offset()).Limit(page.Size).All(&roles)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = roles
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) RemoveUserRole(roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(roleId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid role id: %v", roleId)
			st <- result
			return
		}
		roleDoc := mogo.NewDoc(models.UserRoles{}).(*models.UserRoles)
		// Find role
		err := roleDoc.FindByID(bson.ObjectIdHex(roleId), roleDoc)
		if err != nil {
			result.Error = errors.New("role does not exist")
			result.Success = false
		} else {
			err := roleDoc.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = roleDoc
			}
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) UpdateUserRole(roleId string, servRole models.UserRoles) DataChannel {
	panic("implement me")
}

func (sas MongoServiceAclStore) GetUserRoleById(roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(roleId) {
			result.Error = errors.New("invalid role id")
			result.Success = false
			st <- result
			return
		}
		// Find role
		roleDocs := mogo.NewDoc(models.UserRoles{}).(*models.UserRoles)
		err := roleDocs.FindByID(bson.ObjectIdHex(roleId), roleDocs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = roleDocs
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) GetUserRolePermissions(roleId string, page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(roleId) {
			result.Error = errors.New("invalid role id")
			result.Success = false
			st <- result
			return
		}
		roles := make([]models.UserPermissions, 0)
		roleDocs := mogo.NewDoc(models.UserPermissions{}).(*models.UserPermissions)
		err := roleDocs.Find(bson.M{"role_id": bson.ObjectIdHex(roleId)}).Skip(page.Offset()).Limit(page.Size).All(&roles)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = roles
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) AddUserPermission(roleId string, usrRolePermission models.UserPermissions) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(roleId) {
			result.Error = errors.New("invalid role id")
			result.Success = false
			st <- result
			return
		}
		rolesDoc := mogo.NewDoc(models.UserRoles{}).(*models.UserRoles)
		err := rolesDoc.FindByID(bson.ObjectIdHex(roleId), rolesDoc)
		if err != nil {
			result.Error = errors.New("role not found")
			result.Success = false
			st <- result
			return
		}

		permissionDoc := mogo.NewDoc(usrRolePermission).(*models.UserPermissions)
		if permissionDoc.IsNew() {
			permissionDoc.RoleRef = rolesDoc.ID
			err = permissionDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = permissionDoc
			}
		} else {
			result.Error = errors.New("permission already exists")
			result.Success = false
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) RemoveUserPermission(permissionId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(permissionId) {
			result.Error = errors.New("invalid permission id")
			result.Success = false
			st <- result
			return
		}
		// Find permission
		roleDocs := mogo.NewDoc(models.UserPermissions{}).(*models.UserPermissions)
		err := roleDocs.FindByID(bson.ObjectIdHex(permissionId), roleDocs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			// Delete permission
			err = roleDocs.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = roleDocs
			}
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) UpdateUserPermission(permissionId string, servRole models.UserPermissions) DataChannel {
	panic("implement me")
}

func (sas MongoServiceAclStore) GetUserPermissionById(permissionId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(permissionId) {
			result.Error = errors.New("invalid permission id")
			result.Success = false
			st <- result
			return
		}
		// Find permission
		roleDocs := mogo.NewDoc(models.UserPermissions{}).(*models.UserPermissions)
		err := roleDocs.FindByID(bson.ObjectIdHex(permissionId), roleDocs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = roleDocs
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) RemoveRealmPermission(roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(roleId) {
			result.Error = errors.New("invalid permission id")
			result.Success = false
			st <- result
			return
		}
		// Find permission
		docs := mogo.NewDoc(models.RealmPermissions{}).(*models.RealmPermissions)
		err := docs.FindByID(bson.ObjectIdHex(roleId), docs)
		if err != nil {
			result.Success = false
			result.Error = err
		} else {
			err = docs.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = docs
			}
		}
		st <- result

	}()
	return st
}

func (sas MongoServiceAclStore) GetRealmPermissionById(roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(roleId) {
			result.Error = errors.New("invalid permission id")
			result.Success = false
			st <- result
			return
		}
		// Find permission
		docs := mogo.NewDoc(models.RealmPermissions{}).(*models.RealmPermissions)
		err := docs.FindByID(bson.ObjectIdHex(roleId), docs)
		if err != nil {
			result.Success = false
			result.Error = err
		} else {
			result.Data = docs
		}
		st <- result

	}()
	return st
}

func (sas MongoServiceAclStore) AddRealmRole(servRole models.RealmRoles) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		docs := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
		err := docs.Find(bson.M{"role_name": servRole.RoleName}).One(docs)
		if err == mgo.ErrNotFound {
			roleSrv := mogo.NewDoc(servRole).(*models.RealmRoles)
			err = roleSrv.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = roleSrv
			}
		} else {
			result.Success = false
			result.Error = errors.New("role already exists")
		}
		st <- result

	}()
	return st
}

func (sas MongoServiceAclStore) RemoveRealmRole(roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()

		if !bson.IsObjectIdHex(roleId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid role id: %s", roleId)
			st <- result
			return
		}
		id := bson.ObjectIdHex(roleId)
		docs := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
		err := docs.FindID(id).One(docs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			err = docs.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = docs
			}
		}
		st <- result

	}()

	return st
}

func (sas MongoServiceAclStore) GetRealmRoleById(roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()

		if !bson.IsObjectIdHex(roleId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid role id: %s", roleId)
			st <- result
			return
		}
		id := bson.ObjectIdHex(roleId)
		// Check role exists
		docs := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
		err := docs.FindID(id).One(docs)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = docs
		}
		st <- result

	}()

	return st
}

func (sas MongoServiceAclStore) UpdateRealmRole(roleId string, servRole models.RealmRoles) DataChannel {
	panic("not implemented")
}

func (sas MongoServiceAclStore) GetRealmPermissions(serviceId string, page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()

		if !bson.IsObjectIdHex(serviceId) {
			result.Success = false
			result.Error = fmt.Errorf("invalid service id: %s", serviceId)
			st <- result
			return
		}
		id := bson.ObjectIdHex(serviceId)
		// Fetch roles
		permissions := make([]models.UserPermissions, 0)
		roleDocs := mogo.NewDoc(models.RealmRoles{}).(*models.RealmRoles)
		err := roleDocs.Find(&bson.M{"role_id": id}).Skip(page.Offset()).Limit(page.Size).All(&permissions)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = permissions
		}
		st <- result
	}()
	return st
}

func (sas MongoServiceAclStore) AssignRole(roleId, userId, serviceId string) DataChannel {
	panic("implement me")
}

func (sas MongoServiceAclStore) RemoveRoleAssignment(assignmentId string) DataChannel {
	panic("implement me")
}

func (sas MongoServiceAclStore) GetUserRoles(userId string) DataChannel {
	panic("implement me")
}
