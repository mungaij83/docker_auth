package forms

import "github.com/cesanta/docker_auth/auth_server/models"

type GroupForm struct {
	GroupName   string `json:"group_name"`
	Active      bool   `json:"active"`
	IsDefault   bool   `json:"is_default"`
	Description string `json:"description"`
}

func (g GroupForm) GetGroup() models.Groups {
	grp := models.Groups{}
	grp.GroupName = g.GroupName
	grp.IsDefault = g.IsDefault
	grp.Description = g.Description
	grp.Active = g.Active
	return grp
}

type AttributeForm struct {
	AttributeName  string `json:"attribute_name"`
	AttributeValue string `json:"attribute_value"`
}

func (a AttributeForm) GetGroupAttribute() models.GroupAttributes {
	attr := models.GroupAttributes{}
	attr.AttrValue = a.AttributeValue
	attr.AttrKey = a.AttributeName

	return attr
}

// Role assignment
type RoleAssignmentForm struct {
	RoleId      string `json:"role_id"`
	Active      bool   `json:"active"`
	Description string `json:"description"`
	RoleType    string `json:"role_type"` // User or realm
}

func (raf RoleAssignmentForm) GetGroupUserRole() models.GroupUserRoles {
	r := models.GroupUserRoles{}
	r.Active = raf.Active
	r.Description = raf.Description
	return r
}

func (raf RoleAssignmentForm) GetGroupRealmRole() models.GroupRealmRoles {
	r := models.GroupRealmRoles{}
	r.Active = raf.Active
	r.Description = raf.Description
	return r
}

// User group assignment
type UserAssignmentForm struct {
	UserId      string `json:"user_id"`
	Active      bool   `json:"active"`
	Description string `json:"description"`
	RoleType    string `json:"role_type"` // User or realm
}

func (ua UserAssignmentForm) GetGroupAssignment() models.UserGroups {
	f := models.UserGroups{}
	f.Active = ua.Active
	f.Description = ua.Description
	return f
}

// User group assignment
type ClientAssignmentForm struct {
	ClientId    string `json:"client_id"`
	Active      bool   `json:"active"`
	Description string `json:"description"`
}

func (ua ClientAssignmentForm) GetGroupAssignment() models.ClientGroups {
	f := models.ClientGroups{}
	f.Active = ua.Active
	f.Description = ua.Description
	return f
}
