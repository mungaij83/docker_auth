package authz

import (
	"github.com/cesanta/docker_auth/auth_server/utils"
	"net"
	"testing"
)

func sp(s string) *string {
	return &s
}

func TestValidation(t *testing.T) {
	cases := []struct {
		mc utils.MatchConditions
		ok bool
	}{
		// Valid stuff
		{utils.MatchConditions{}, true},
		{utils.MatchConditions{Account: sp("foo")}, true},
		{utils.MatchConditions{Account: sp("foo?*")}, true},
		{utils.MatchConditions{Account: sp("/foo.*/")}, true},
		{utils.MatchConditions{Type: sp("foo")}, true},
		{utils.MatchConditions{Type: sp("foo?*")}, true},
		{utils.MatchConditions{Type: sp("/foo.*/")}, true},
		{utils.MatchConditions{Name: sp("foo")}, true},
		{utils.MatchConditions{Name: sp("foo?*")}, true},
		{utils.MatchConditions{Name: sp("/foo.*/")}, true},
		{utils.MatchConditions{Service: sp("foo")}, true},
		{utils.MatchConditions{Service: sp("foo?*")}, true},
		{utils.MatchConditions{Service: sp("/foo.*/")}, true},
		{utils.MatchConditions{IP: sp("192.168.0.1")}, true},
		{utils.MatchConditions{IP: sp("192.168.0.0/16")}, true},
		{utils.MatchConditions{IP: sp("2001:db8::1")}, true},
		{utils.MatchConditions{IP: sp("2001:db8::/48")}, true},
		{utils.MatchConditions{Labels: map[string]string{"foo": "bar"}}, true},
		// Invalid stuff
		{utils.MatchConditions{Account: sp("/foo?*/")}, false},
		{utils.MatchConditions{Type: sp("/foo?*/")}, false},
		{utils.MatchConditions{Name: sp("/foo?*/")}, false},
		{utils.MatchConditions{Service: sp("/foo?*/")}, false},
		{utils.MatchConditions{IP: sp("192.168.0.1/100")}, false},
		{utils.MatchConditions{IP: sp("192.168.0.*")}, false},
		{utils.MatchConditions{IP: sp("foo")}, false},
		{utils.MatchConditions{IP: sp("2001:db8::/222")}, false},
		{utils.MatchConditions{Labels: map[string]string{"foo": "/bar?*/"}}, false},
	}
	for i, c := range cases {
		result := utils.ValidateMatchConditions(&c.mc)
		if c.ok && result != nil {
			t.Errorf("%d: %q: expected to pass, got %s", i, c.mc, result)
		} else if !c.ok && result == nil {
			t.Errorf("%d: %q: expected to fail, but it passed", i, c.mc)
		}
	}
}

func TestMatching(t *testing.T) {
	ai1 := utils.AuthRequestInfo{Account: "foo", Type: "bar", Name: "baz", Service: "notary"}
	ai2 := utils.AuthRequestInfo{Account: "foo", Type: "bar", Name: "baz", Service: "notary",
		Labels: map[string][]string{"group": {"admins", "VIP"}}}
	ai3 := utils.AuthRequestInfo{Account: "foo", Type: "bar", Name: "admins/foo", Service: "notary",
		Labels: map[string][]string{"group": {"admins", "VIP"}}}
	ai4 := utils.AuthRequestInfo{Account: "foo", Type: "bar", Name: "VIP/api", Service: "notary",
		Labels: map[string][]string{"group": {"admins", "VIP"}, "project": []string{"api", "frontend"}}}
	ai5 := utils.AuthRequestInfo{Account: "foo", Type: "bar", Name: "devs/api", Service: "notary",
		Labels: map[string][]string{"group": {"admins", "VIP"}, "project": []string{"api", "frontend"}}}
	cases := []struct {
		mc      utils.MatchConditions
		ai      utils.AuthRequestInfo
		matches bool
	}{
		{utils.MatchConditions{}, ai1, true},
		{utils.MatchConditions{Account: sp("foo")}, ai1, true},
		{utils.MatchConditions{Account: sp("foo"), Type: sp("bar")}, ai1, true},
		{utils.MatchConditions{Account: sp("foo"), Type: sp("baz")}, ai1, false},
		{utils.MatchConditions{Account: sp("fo?"), Type: sp("b*"), Name: sp("/z$/")}, ai1, true},
		{utils.MatchConditions{Account: sp("fo?"), Type: sp("b*"), Name: sp("/^z/")}, ai1, false},
		{utils.MatchConditions{Name: sp("${account}")}, utils.AuthRequestInfo{Account: "foo", Name: "foo"}, true}, // Var subst
		{utils.MatchConditions{Name: sp("/${account}_.*/")}, utils.AuthRequestInfo{Account: "foo", Name: "foo_x"}, true},
		{utils.MatchConditions{Name: sp("/${account}_.*/")}, utils.AuthRequestInfo{Account: ".*", Name: "foo_x"}, false}, // Quoting
		{utils.MatchConditions{Account: sp(`/^(.+)@test\.com$/`), Name: sp(`${account:1}/*`)}, utils.AuthRequestInfo{Account: "john.smith@test.com", Name: "john.smith/test"}, true},
		{utils.MatchConditions{Account: sp(`/^(.+)@test\.com$/`), Name: sp(`${account:3}/*`)}, utils.AuthRequestInfo{Account: "john.smith@test.com", Name: "john.smith/test"}, false},
		{utils.MatchConditions{Account: sp(`/^(.+)@(.+?).test\.com$/`), Name: sp(`${account:1}-${account:2}/*`)}, utils.AuthRequestInfo{Account: "john.smith@it.test.com", Name: "john.smith-it/test"}, true},
		{utils.MatchConditions{Service: sp("notary"), Type: sp("bar")}, ai1, true},
		{utils.MatchConditions{Service: sp("notary"), Type: sp("baz")}, ai1, false},
		{utils.MatchConditions{Service: sp("notary1"), Type: sp("bar")}, ai1, false},
		// IP matching
		{utils.MatchConditions{IP: sp("127.0.0.1")}, utils.AuthRequestInfo{IP: nil}, false},
		{utils.MatchConditions{IP: sp("127.0.0.1")}, utils.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 1)}, true},
		{utils.MatchConditions{IP: sp("127.0.0.1")}, utils.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 2)}, false},
		{utils.MatchConditions{IP: sp("127.0.0.2")}, utils.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 1)}, false},
		{utils.MatchConditions{IP: sp("127.0.0.0/8")}, utils.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 1)}, true},
		{utils.MatchConditions{IP: sp("127.0.0.0/8")}, utils.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 2)}, true},
		{utils.MatchConditions{IP: sp("2001:db8::1")}, utils.AuthRequestInfo{IP: nil}, false},
		{utils.MatchConditions{IP: sp("2001:db8::1")}, utils.AuthRequestInfo{IP: net.ParseIP("2001:db8::1")}, true},
		{utils.MatchConditions{IP: sp("2001:db8::1")}, utils.AuthRequestInfo{IP: net.ParseIP("2001:db8::2")}, false},
		{utils.MatchConditions{IP: sp("2001:db8::2")}, utils.AuthRequestInfo{IP: net.ParseIP("2001:db8::1")}, false},
		{utils.MatchConditions{IP: sp("2001:db8::/48")}, utils.AuthRequestInfo{IP: net.ParseIP("2001:db8::1")}, true},
		{utils.MatchConditions{IP: sp("2001:db8::/48")}, utils.AuthRequestInfo{IP: net.ParseIP("2001:db8::2")}, true},
		// Label matching
		{utils.MatchConditions{Labels: map[string]string{"foo": "bar"}}, ai1, false},
		{utils.MatchConditions{Labels: map[string]string{"foo": "bar"}}, ai2, false},
		{utils.MatchConditions{Labels: map[string]string{"group": "admins"}}, ai2, true},
		{utils.MatchConditions{Labels: map[string]string{"foo": "bar", "group": "admins"}}, ai2, false}, // "and" logic
		{utils.MatchConditions{Labels: map[string]string{"group": "VIP"}}, ai2, true},
		{utils.MatchConditions{Labels: map[string]string{"group": "a*"}}, ai2, true},
		{utils.MatchConditions{Labels: map[string]string{"group": "/(admins|VIP)/"}}, ai2, true},
		// // Label placeholder matching
		{utils.MatchConditions{Name: sp("${labels:group}/*")}, ai1, false},                 // no labels
		{utils.MatchConditions{Name: sp("${labels:noexist}/*")}, ai2, false},               // wrong labels
		{utils.MatchConditions{Name: sp("${labels:group}/*")}, ai3, true},                  // match label
		{utils.MatchConditions{Name: sp("${labels:noexist}/*")}, ai3, false},               // missing label
		{utils.MatchConditions{Name: sp("${labels:group}/${labels:project}")}, ai4, true},  // multiple label match success
		{utils.MatchConditions{Name: sp("${labels:group}/${labels:noexist}")}, ai4, false}, // multiple label match fail
		{utils.MatchConditions{Name: sp("${labels:group}/${labels:project}")}, ai4, true},  // multiple label match success
		{utils.MatchConditions{Name: sp("${labels:group}/${labels:noexist}")}, ai4, false}, // multiple label match fail wrong label
		{utils.MatchConditions{Name: sp("${labels:group}/${labels:project}")}, ai5, false}, // multiple label match fail. right label, wrong value
	}
	for i, c := range cases {
		if result := c.mc.Matches(&c.ai); result != c.matches {
			t.Errorf("%d: %#v vs %#v: expected %t, got %t", i, c.mc, c.ai, c.matches, result)
		}
	}
}
