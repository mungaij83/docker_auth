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
)

type MongoGroupStore struct {
	*MongoStore
}

func NewMongoGroupStore(s *MongoStore) GroupStore {
	mogo.ModelRegistry.Register(models.Groups{}, models.GroupRealmRoles{}, models.GroupUserRoles{}, models.GroupAttributes{}, models.Scope{})

	return MongoGroupStore{s}
}

func (gs MongoGroupStore) NewGroupDoc(g *models.Groups) *models.Groups {
	if g != nil {
		return mogo.NewDoc(*g).(*models.Groups)
	} else {
		return mogo.NewDoc(models.Groups{}).(*models.Groups)
	}
}

func (gs MongoGroupStore) AddScope(serviceId string, scope models.Scope) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Service exists
		_, err := gs.Services().GetServiceById(serviceId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		doc := mogo.NewDoc(scope).(*models.Scope)
		doc.ServiceId = bson.ObjectIdHex(serviceId)
		glog.V(2).Infof("add scope: %+v", scope)
		err = doc.Save()
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = scope
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) ListServiceScopes(serviceId string, page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		searchType := "id"
		if !bson.IsObjectIdHex(serviceId) {
			searchType = "name"
		}
		var err error
		scopesDoc := mogo.NewDoc(models.Scope{}).(*models.Scope)
		scopes := make([]models.Scope, 0)
		if searchType == "id" {
			err = scopesDoc.Find(bson.M{"service_id": bson.ObjectIdHex(serviceId)}).Limit(page.Size).Skip(page.Offset()).All(&scopes)
		} else {
			service, err := gs.Services().GetServiceByName(serviceId)
			if err == nil {
				err = scopesDoc.Find(bson.M{"service_id": service.ID}).Limit(page.Size).Skip(page.Offset()).All(&scopes)
			}
		}
		if err != nil {
			result.Success = false
			result.Error = err
		} else {
			result.Data = scopes
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) GetScopeById(scopeId string) (*models.Scope, error) {
	if !bson.IsObjectIdHex(scopeId) {
		return nil, errors.New("invalid service id")
	}
	scopeDoc := mogo.NewDoc(models.Scope{}).(*models.Scope)
	err := scopeDoc.FindByID(bson.ObjectIdHex(scopeId), scopeDoc)
	return scopeDoc, err
}

func (gs MongoGroupStore) GetScope(scopeId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		doc, err := gs.GetScopeById(scopeId)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = doc
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) RemoveScope(scopeId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		doc, err := gs.GetScopeById(scopeId)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			err = doc.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = doc
			}
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) AddUserRoleToScope(scopeId, roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Find scope
		scope, err := gs.GetScopeById(scopeId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Find role
		role, err := gs.AclStore().UserRoleById(roleId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Check if exists
		exists := -1
		for idx, i := range scope.RolesRefs {
			if bson.IsObjectIdHex(i) && bson.ObjectIdHex(i) == role.ID {
				exists = idx
				break
			}
		}
		// Assign role
		if exists > 0 {
			result.Error = errors.New("role already assigned")
			result.Success = false
		} else {
			scope.RolesRefs = append(scope.RolesRefs, roleId)
			err = scope.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = scope
			}
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) RemoveUserRoleFromScope(scopeId, roleId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Find scope
		scope, err := gs.GetScopeById(scopeId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Find role
		if !bson.IsObjectIdHex(roleId) {
			result.Error = errors.New("invalid role identifier")
			result.Success = false
			st <- result
			return
		}
		role := bson.ObjectIdHex(roleId)
		// Check if exists
		exists := -1
		for idx, i := range scope.RolesRefs {
			if bson.IsObjectIdHex(i) && bson.ObjectIdHex(i) == role {
				exists = idx
				break
			}
		}
		// Assign role
		if exists < 0 {
			result.Error = errors.New("role not assigned")
			result.Success = false
		} else {
			scope.RolesRefs = append(scope.RolesRefs[:exists], scope.RolesRefs[exists+1:]...)
			err = scope.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = scope
			}
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) AddGroup(g models.Groups) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		existingGroup := gs.NewGroupDoc(nil)
		err := existingGroup.Find(bson.M{"group_name": g.GroupName}).One(existingGroup)
		if err == mgo.ErrNotFound {
			// Create group
			groupDoc := gs.NewGroupDoc(&g)
			err = groupDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = groupDoc
			}
		} else {
			result.Error = fmt.Errorf("group exists")
			result.Success = false
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) GetGroupById(groupId string) (*models.Groups, error) {
	if !bson.IsObjectIdHex(groupId) {
		return nil, fmt.Errorf("invalid group id: %v", groupId)
	}
	groupDoc := gs.NewGroupDoc(nil)
	err := groupDoc.FindByID(bson.ObjectIdHex(groupId), groupDoc)
	return groupDoc, err
}
func (gs MongoGroupStore) GetGroup(groupId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Get groups
		groupDoc, err := gs.GetGroupById(groupId)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = groupDoc
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) ListGroups(page Page) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Get groups
		groups := make([]models.Groups, 0)
		groupDoc := gs.NewGroupDoc(nil)
		err := groupDoc.Find(bson.M{}).Skip(page.Offset()).Limit(page.Size).All(&groups)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = groups
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) RemoveGroup(groupId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		groupDoc, err := gs.GetGroupById(groupId)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			// Delete group
			err = groupDoc.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = groupDoc
			}
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) AddAttributeOrUpdate(groupId string, attr models.GroupAttributes) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		groupDoc, err := gs.GetGroupById(groupId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// add attribute or update existing
		if len(groupDoc.ExtraGroupAttributes) == 0 {
			groupDoc.ExtraGroupAttributes = make([]models.GroupAttributes, 0)
		}
		// Find existing
		existId := -1
		for idx, i := range groupDoc.ExtraGroupAttributes {
			if i.AttrKey == attr.AttrKey {
				existId = idx
			}
		}
		if existId >= 0 {
			groupDoc.ExtraGroupAttributes[existId].AttrValue = attr.AttrValue
		} else {
			attr.ID = bson.NewObjectId()
			groupDoc.ExtraGroupAttributes = append(groupDoc.ExtraGroupAttributes, attr)
		}
		err = groupDoc.Save()
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = groupDoc
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) GetUserRoles(userId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(userId) {
			result.Error = errors.New("invalid user identifier")
			result.Success = false
			st <- result
			return
		}
		userGroupDocs := mogo.NewDoc(models.UserGroups{}).(*models.UserGroups)
		ids := make([]bson.ObjectId, 0)
		err := userGroupDocs.Find(nil).C().Find(bson.M{"user_id": bson.ObjectIdHex(userId)}).Distinct("group_id", &ids)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Get all roles for these groups
		userRoles := make([]utils.StringMap, 0)
		for _, i := range ids {
			res := <-gs.GetGroupRoles(i.Hex(), "user")
			if !res.HasError() {
				glog.V(2).Infof("roles: [%v]+ %+v", i, utils.ToJson(res.Data))
				if ss, ok := res.Data.([]utils.StringMap); ok {
					userRoles = append(userRoles, ss...)
				}
			} else {
				glog.V(2).Infof("failed to get roles for group: %v: %+v", i, res)
			}
		}
		// return roles
		result.Data = userRoles
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) GetClientRoles(clientId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(clientId) {
			result.Error = errors.New("invalid client identifier")
			result.Success = false
			st <- result
			return
		}
		userGroupDocs := mogo.NewDoc(models.ClientGroups{}).(*models.ClientGroups)
		groupIds := make([]bson.ObjectId, 0)
		err := userGroupDocs.Find(nil).C().Find(bson.M{"client_id": bson.ObjectIdHex(clientId)}).Distinct("group_id", &groupIds)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Get all realm roles for these groups
		userRoles := make([]utils.StringMap, 0)
		for _, i := range groupIds {
			res := <-gs.GetGroupRoles(i.Hex(), "realm")
			if !res.HasError() {
				glog.V(2).Infof("roles: [%v]+ %+v", i, utils.ToJson(res.Data))
				if ss, ok := res.Data.([]utils.StringMap); ok {
					userRoles = append(userRoles, ss...)
				}
			} else {
				glog.V(2).Infof("failed to get roles for group: %v: %+v", i, res)
			}
		}
		// return client roles
		result.Data = userRoles
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) GetUserGroups(userId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(userId) {
			result.Error = errors.New("invalid user identifier")
			result.Success = false
			st <- result
			return
		}
		userGroupDocs := mogo.NewDoc(models.UserGroups{}).(*models.UserGroups)
		ids := make([]bson.ObjectId, 0)
		err := userGroupDocs.Find(nil).C().Find(bson.M{"user_id": bson.ObjectIdHex(userId)}).Distinct("group_id", &ids)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Get all roles for these groups
		userGroups := make([]utils.StringMap, 0)

		groupDocs := mogo.NewDoc(models.Groups{}).(*models.Groups)
		err = groupDocs.Find(bson.M{
			"_id": bson.M{
				"$in": ids,
			},
		}).All(&userGroups)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = userGroups
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) GetClientGroups(clientId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(clientId) {
			result.Error = errors.New("invalid client identifier")
			result.Success = false
			st <- result
			return
		}
		userGroupDocs := mogo.NewDoc(models.ClientGroups{}).(*models.ClientGroups)
		groupIds := make([]bson.ObjectId, 0)
		err := userGroupDocs.Find(nil).C().Find(bson.M{"client_id": bson.ObjectIdHex(clientId)}).Distinct("group_id", &groupIds)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Get all groups assigned for this client
		clientGroups := make([]utils.StringMap, 0)

		groupDocs := mogo.NewDoc(models.Groups{}).(*models.Groups)
		err = groupDocs.Find(bson.M{
			"_id": bson.M{
				"$in": groupIds,
			},
		}).All(&clientGroups)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = clientGroups
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) GeScopeRoles(scopeId string, gType string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(scopeId) {
			result.Error = errors.New("invalid scope identifier")
			result.Success = false
			st <- result
			st <- result
			return
		}
		scope, err := gs.GetScopeById(scopeId)
		if err != nil {
			result.Error = errors.New("invalid scope name")
			result.Success = false
			st <- result
			st <- result
			return
		}
		ids := make([]bson.ObjectId, 0)
		for _, id := range scope.RolesRefs {
			ids = append(ids, bson.ObjectIdHex(id))
		}
		query := make([]bson.M, 0)
		query = append(query, bson.M{"$match": bson.M{
			"_id": bson.M{
				"$in": ids,
			},
		}})
		var roleTableName string
		roleTableName, _ = gs.GetTableName(models.UserRoles{})

		var permissionTableName string
		permissionTableName, _ = gs.GetTableName(models.UserPermissions{})
		query = append(query, bson.M{"$lookup": bson.M{
			"from":         permissionTableName,
			"localField":   "_id",
			"foreignField": "role_id",
			"as":           "permissions",
		}})

		session := gs.Master().Session.New().Copy()
		defer session.Close()
		db, _ := session.DatabaseNames()
		pipe := session.DB(db[0]).C(roleTableName).Pipe(query)
		bb := make([]utils.StringMap, 0)
		err = pipe.All(&bb)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = bb
		}
		st <- result

	}()
	return st
}
func (gs MongoGroupStore) GetGroupRoles(groupId string, gType string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(groupId) {
			result.Error = errors.New("invalid group identifier")
			result.Success = false
			st <- result
			return
		}
		query := make([]bson.M, 0)
		// Filter group
		var roleTableName string
		query = append(query, bson.M{"$match": bson.M{"group_id": bson.ObjectIdHex(groupId)}})
		if gType == "user" {
			roleTableName, _ = gs.GetTableName(models.UserRoles{})
			// lookup
			query = append(query, bson.M{"$lookup": bson.M{
				"from":         roleTableName,
				"localField":   "user_role_id",
				"foreignField": "_id",
				"as":           "groupRoles",
			}})
		} else {
			roleTableName, _ = gs.GetTableName(models.RealmRoles{})
			// lookup
			query = append(query, bson.M{"$lookup": bson.M{
				"from":         roleTableName,
				"localField":   "user_role_id",
				"foreignField": "_id",
				"as":           "groupRoles",
			}})
		}

		//{"$replaceRoot":{"newRoot":{"$mergeObjects":[{"$arrayElemAt":["$groupRoles",0]},"$$ROOT"]}}}
		options := make([]interface{}, 0)
		options = append(options, bson.M{"$arrayElemAt": []interface{}{"$groupRoles", 0}})
		options = append(options, "$$ROOT")
		//query = append(query, bson.M{"$unwind": "$groupRoles"})
		query = append(query, bson.M{
			"$replaceRoot": bson.M{"newRoot": bson.M{"$mergeObjects": options}},
		})
		query = append(query, bson.M{"$project": bson.M{"groupRoles": 0}})

		var err error
		var collectionName string
		session := gs.Master().Session.New().Copy()
		defer session.Close()
		db, _ := session.DatabaseNames()
		// Get type roles
		if gType == "user" {
			collectionName, err = gs.GetTableName(models.GroupUserRoles{})
			glog.V(2).Infof("Not exists[%v]: %v", db[0], collectionName)
			// Lookup user role permissions
			userPermission, _ := gs.GetTableName(models.UserPermissions{})
			query = append(query, bson.M{"$lookup": bson.M{
				"from":         userPermission,
				"localField":   "user_role_id",
				"foreignField": "role_id",
				"as":           "permissions",
			}})
		} else {
			realPermission, _ := gs.GetTableName(models.RealmPermissions{})
			collectionName, _ = gs.GetTableName(models.GroupRealmRoles{})
			glog.V(2).Infof("Not exists[%v]: %v", db[0], collectionName)
			// Lookup realm permissions
			query = append(query, bson.M{"$lookup": bson.M{
				"from":         realPermission,
				"localField":   "realm_role_id",
				"foreignField": "role_id",
				"as":           "permissions",
			}})
		}
		// Execute pipeline
		pipe := session.DB(db[0]).C(collectionName).Pipe(query)
		bb := make([]utils.StringMap, 0)
		err = pipe.All(&bb)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = bb
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) RemoveAttribute(attrId, groupId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Validate attribute id
		if !bson.IsObjectIdHex(attrId) {
			result.Error = fmt.Errorf("invalid group attr Id")
			result.Success = false
			st <- result
			return
		}
		groupDoc, err := gs.GetGroupById(groupId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// add attribute or update existing
		if len(groupDoc.ExtraGroupAttributes) == 0 {
			groupDoc.ExtraGroupAttributes = make([]models.GroupAttributes, 0)
		}
		// Find existing
		aID := bson.ObjectIdHex(attrId)
		existId := -1
		for idx, i := range groupDoc.ExtraGroupAttributes {
			if i.ID == aID {
				existId = idx
			}
		}
		if existId >= 0 {
			groupDoc.ExtraGroupAttributes = append(groupDoc.ExtraGroupAttributes[:existId], groupDoc.ExtraGroupAttributes[existId+1:]...)
			err = groupDoc.Save()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = groupDoc
			}
		} else {
			result.Error = fmt.Errorf("attribute does not exist: %v", attrId)
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) AddUser(userId string, groupId string, userGroup models.UserGroups) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Find group to assign
		groupDoc, err := gs.GetGroupById(groupId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Find user to assign
		user, err := gs.Users().GetUserById(userId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Group assignment
		userGroup.GroupId = groupDoc.ID
		userGroup.UserId = user.ID
		userGroup.Active = true
		userGroupDoc := mogo.NewDoc(userGroup).(*models.UserGroups)
		err = userGroupDoc.Save()
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = userGroupDoc
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) RemoveUserAssignment(assignmentId string) DataChannel {
	panic("implement me")
}

func (gs MongoGroupStore) AddClient(clientId, groupId string, assignment models.ClientGroups) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		// Validate group exists
		groupDoc, err := gs.GetGroupById(groupId)
		if err != nil {
			glog.V(2).Infof("Group not found: %v", err)
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Validate client exists
		assignment.GroupId = groupDoc.ID
		clientDoc, err := gs.Clients().ClientById(clientId)
		if err != nil {
			glog.V(2).Infof("Client not found: %v", err)
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		assignment.ClientId = clientDoc.ID
		// Save assignment
		assignmentDoc := mogo.NewDoc(assignment).(*models.ClientGroups)
		err = assignmentDoc.Save()
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = assignmentDoc
		}
		st <- result

	}()
	return st
}

func (gs MongoGroupStore) RemoveClientAssignment(assignmentId string) DataChannel {
	panic("implement me")
}

func (gs MongoGroupStore) AssignRealmRole(groupId string, roleId string, realmAssignment models.GroupRealmRoles) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		_, err := gs.GetGroupById(groupId)
		if err != nil {
			glog.V(2).Infof("invalid group id: %v", err)
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		_, err = gs.AclStore().RealmRoleById(roleId)
		if err != nil {
			glog.V(2).Infof("invalid role id: %v", err)
			result.Error = err
			result.Success = false
			st <- result
			return
		}

		gRealmAssignmentDoc := mogo.NewDoc(realmAssignment).(*models.GroupRealmRoles)
		//realmAssignment.ID = bson.NewObjectId()
		gRealmAssignmentDoc.RealmRoleId = bson.ObjectIdHex(roleId)
		gRealmAssignmentDoc.GroupId = bson.ObjectIdHex(groupId)
		glog.Infof("Saving document[%s]: %v", groupId, roleId, utils.ToJson(realmAssignment))
		err = gRealmAssignmentDoc.Save()
		if err != nil {

			glog.Infof("Saving document: %v", err)
			result.Error = err
			result.Success = false
		} else {
			result.Data = gRealmAssignmentDoc
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) RemoveRealmRole(assignmentId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(assignmentId) {
			result.Error = errors.New("assignment id is invalid")
			result.Success = false
			st <- result
			return
		}

		assingmentDoc := mogo.NewDoc(models.GroupRealmRoles{}).(*models.GroupRealmRoles)
		err := assingmentDoc.FindByID(bson.ObjectIdHex(assignmentId), assingmentDoc)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			err = assingmentDoc.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = assingmentDoc
			}
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) AssignUserRole(groupId string, roleId string, roleAssignment models.GroupUserRoles) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		groupDoc, err := gs.GetGroupById(groupId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		roleDoc, err := gs.AclStore().UserRoleById(roleId)
		if err != nil {
			result.Error = err
			result.Success = false
			st <- result
			return
		}
		// Save user role assignment
		roleAssignmentDoc := mogo.NewDoc(roleAssignment).(*models.GroupUserRoles)
		roleAssignmentDoc.UserRoleId = roleDoc.ID
		roleAssignmentDoc.GroupId = groupDoc.ID
		err = roleAssignmentDoc.Save()
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Data = roleAssignmentDoc
		}
		st <- result
	}()
	return st
}

func (gs MongoGroupStore) RemoveUserRole(assignmentId string) DataChannel {
	st := make(DataChannel)
	go func() {
		result := NewResultStore()
		if !bson.IsObjectIdHex(assignmentId) {
			result.Error = errors.New("assignment id is invalid")
			result.Success = false
			st <- result
			return
		}
		// Find user roles
		assingmentDoc := mogo.NewDoc(models.GroupUserRoles{}).(*models.GroupUserRoles)
		err := assingmentDoc.FindByID(bson.ObjectIdHex(assignmentId), assingmentDoc)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			// Remove role
			err = assingmentDoc.Remove()
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Data = assingmentDoc
			}
		}
		st <- result
	}()
	return st
}
