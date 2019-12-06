package authz

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/cesanta/glog"
)
type aclAuthorizer struct {
	acl utils.ACL
}

// NewACLAuthorizer Creates a new static authorizer with ACL that have been read from the config file
func NewACLAuthorizer(acl utils.ACL) (utils.Authorizer, error) {
	if err := utils.ValidateACL(acl); err != nil {
		return nil, err
	}
	glog.V(1).Infof("Created ACL Authorizer with %d entries", len(acl))
	return &aclAuthorizer{acl: acl}, nil
}

func (aa *aclAuthorizer) Authorize(ai *utils.AuthRequestInfo) ([]string, error) {
	for _, e := range aa.acl {
		matched := e.Matches(ai)
		if matched {
			glog.V(2).Infof("%s matched %s (Comment: %s)", ai, e, e.Comment)
			if len(*e.Actions) == 1 && (*e.Actions)[0] == "*" {
				return ai.Actions, nil
			}
			return StringSetIntersection(ai.Actions, *e.Actions), nil
		}
	}
	return nil, utils.NoMatch
}

func (aa *aclAuthorizer) Stop() {
	// Nothing to do.
}

func (aa *aclAuthorizer) Name() string {
	return "static ACL"
}
