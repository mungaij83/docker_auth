package forms

import "github.com/cesanta/docker_auth/auth_server/models"

type ScopeForm struct {
	ScopeName   string `json:"scope_name"`
	Active      bool   `json:"active"`
	Description string `json:"description"`
}

func (sf ScopeForm) GetScope() models.Scope {
	s := models.Scope{}
	s.Description = sf.Description
	s.Active = sf.Active
	s.ScopeName = sf.ScopeName
	return s
}
