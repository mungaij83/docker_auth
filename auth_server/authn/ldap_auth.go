/*
   Copyright 2015 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authn

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"io/ioutil"
	"strings"

	"github.com/cesanta/glog"
	"github.com/go-ldap/ldap"
)

type LDAPAuth struct {
	config *utils.LDAPAuthConfig
}

func NewLDAPAuth(c *utils.LDAPAuthConfig) (*LDAPAuth, error) {
	if c.TLS == "" && strings.HasSuffix(c.Addr, ":636") {
		c.TLS = "always"
	}
	return &LDAPAuth{
		config: c,
	}, nil
}

//How to authenticate user, please refer to https://github.com/go-ldap/ldap/blob/master/example_test.go#L166
func (la *LDAPAuth) Authenticate(account string, password utils.PasswordString, realm string) (bool, *utils.PrincipalDetails, error) {
	if account == "" || password == "" {
		return false, nil, utils.NoMatch
	}
	l, err := la.ldapConnection()
	if err != nil {
		glog.V(1).Infof("Failed to get connection: %v", err)
		return false, nil, err
	}
	defer l.Close()

	// First bind with a read only user, to prevent the following search won't perform any write action
	if bindErr := la.bindReadOnlyUser(l); bindErr != nil {
		glog.V(1).Infof("Failed to bind read-only user: %v", bindErr)
		return false, nil, bindErr
	}

	account = la.escapeAccountInput(account)

	filter := la.getFilter(account)

	labelAttributes, labelsConfigErr := la.getLabelAttributes()
	if labelsConfigErr != nil {
		glog.V(1).Infof("Failed to get label attributes: %v", labelsConfigErr)
		return false, nil, labelsConfigErr
	}
	glog.V(1).Infof("Label attributes: %v<=> %v", labelAttributes, filter)
	accountEntryDN, entryAttrMap, uSearchErr := la.ldapSearch(l, &la.config.Base, &filter, &labelAttributes)
	if uSearchErr != nil {
		glog.V(1).Infof("Failed to search: %v", uSearchErr)
		return false, nil, uSearchErr
	}
	glog.V(1).Infof("Attribute map[%v],%v", accountEntryDN, entryAttrMap)
	if accountEntryDN == "" {
		return false, nil, utils.NoMatch // User does not exist
	}

	glog.V(1).Infof("Entry map: %v", entryAttrMap)
	// Bind as the user to verify their password
	if len(accountEntryDN) > 0 {
		err := l.Bind(accountEntryDN, string(password))
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				return false, nil, nil
			}
			return false, nil, err
		}
	}
	// Rebind as the read only user for any futher queries
	if bindErr := la.bindReadOnlyUser(l); bindErr != nil {
		return false, nil, bindErr
	}

	// Extract labels from the attribute values
	_, labelsExtractErr := la.getLabelsFromMap(entryAttrMap)
	if labelsExtractErr != nil {
		return false, nil, labelsExtractErr
	}

	// Rebind as the read only user for any futher queries
	if bindErr := la.bindReadOnlyUser(l); bindErr != nil {
		glog.V(1).Infof("Groups map: %v", )
		return false, nil, bindErr
	}
	principal := utils.PrincipalDetails{
		Username:  account,
		Active:    true,
		RealmName: realm,
		Roles:     make([]utils.AuthzResult, 0),
	}

	// gFilter:=la.getGroupFilter(account)
	// // Extract roles(scope) from user account
	// accountRoles, groupAttrMap, gSearchErr := la.ldapSearch(l, &la.config.Base, &gFilter, &labelAttributes)
	// if gSearchErr != nil {
	// 	glog.V(2).Infof("Group Error: %v",gSearchErr)
	// 	return false, nil, gSearchErr
	// }
	// glog.V(1).Infof("Groups map[%v]: %v",account,accountRoles,groupAttrMap)
	return true, &principal, nil
}

func (la *LDAPAuth) bindReadOnlyUser(l *ldap.Conn) error {
	if la.config.BindDN != "" {
		var passwordStr string
		if la.config.BindPasswordFile != "" {
			password, err := ioutil.ReadFile(la.config.BindPasswordFile)
			if err != nil {
				return err

			}
			passwordStr = strings.TrimSpace(string(password))
		} else {
			passwordStr = strings.TrimSpace(la.config.BindPassword)
		}
		glog.V(2).Infof("Password: %s", passwordStr)
		glog.V(2).Infof("Bind read-only user (DN = %s)", la.config.BindDN)
		err := l.Bind(la.config.BindDN, passwordStr)
		if err != nil {
			return err
		}
	}
	return nil
}

//To prevent LDAP injection, some characters must be escaped for searching
//e.g. char '\' will be replaced by hex '\5c'
//Filter meta chars are choosen based on filter complier code
//https://github.com/go-ldap/ldap/blob/master/filter.go#L159
func (la *LDAPAuth) escapeAccountInput(account string) string {
	r := strings.NewReplacer(
		`\`, `\5c`,
		`(`, `\28`,
		`)`, `\29`,
		`!`, `\21`,
		`*`, `\2a`,
		`&`, `\26`,
		`|`, `\7c`,
		`=`, `\3d`,
		`>`, `\3e`,
		`<`, `\3c`,
		`~`, `\7e`,
	)
	return r.Replace(account)
}

func (la *LDAPAuth) ldapConnection() (*ldap.Conn, error) {
	var l *ldap.Conn
	var err error

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	if !la.config.InsecureTLSSkipVerify {
		addr := strings.Split(la.config.Addr, ":")
		if la.config.CACertificate != "" {
			pool := x509.NewCertPool()
			pem, err := ioutil.ReadFile(la.config.CACertificate)
			if err != nil {
				return nil, fmt.Errorf("error loading CA File: %s", err)
			}
			ok := pool.AppendCertsFromPEM(pem)
			if !ok {
				return nil, fmt.Errorf("error loading CA File: Couldn't parse PEM in: %s", la.config.CACertificate)
			}
			tlsConfig = &tls.Config{InsecureSkipVerify: false, ServerName: addr[0], RootCAs: pool}
		} else {
			tlsConfig = &tls.Config{InsecureSkipVerify: false, ServerName: addr[0]}
		}
	}

	if la.config.TLS == "" || la.config.TLS == "none" || la.config.TLS == "starttls" {
		glog.V(2).Infof("Dial: starting...%s", la.config.Addr)
		l, err = ldap.Dial("tcp", fmt.Sprintf("%s", la.config.Addr))
		if err == nil && la.config.TLS == "starttls" {
			glog.V(2).Infof("StartTLS...")
			if tlserr := l.StartTLS(tlsConfig); tlserr != nil {
				return nil, tlserr
			}
		}
	} else if la.config.TLS == "always" {
		glog.V(2).Infof("DialTLS: starting...%s", la.config.Addr)
		l, err = ldap.DialTLS("tcp", fmt.Sprintf("%s", la.config.Addr), tlsConfig)
	}
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (la *LDAPAuth) getFilter(account string) string {
	filter := strings.NewReplacer("${account}", account).Replace(la.config.Filter)
	glog.V(2).Infof("search filter is %s", filter)
	return filter
}
func (la *LDAPAuth) getGroupFilter(account string) string {
	filter := strings.NewReplacer("${account}", account).Replace(la.config.GroupFilter)
	glog.V(2).Infof("Group filter is %s", filter)
	return filter
}

//ldap search and return required attributes' value from searched entries
//default return entry's DN value if you leave attrs array empty
func (la *LDAPAuth) ldapSearch(l *ldap.Conn, baseDN *string, filter *string, attrs *[]string) (string, map[string][]string, error) {
	if l == nil {
		return "", nil, fmt.Errorf("no LDAP connection")
	}
	glog.V(2).Infof("Searching...basedDN:%s, filter:%s", *baseDN, *filter)
	searchRequest := ldap.NewSearchRequest(
		*baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		*filter,
		*attrs,
		nil)
	sr, err := l.Search(searchRequest)
	if err != nil {
		glog.V(2).Infof("Failed to search: %v", err)
		return "", nil, err
	}

	if len(sr.Entries) == 0 {
		return "", nil, nil // User does not exist
	} else if len(sr.Entries) > 1 {
		return "", nil, fmt.Errorf("too many entries returned")
	}

	attributes := make(map[string][]string)
	var entryDn string
	for _, entry := range sr.Entries {
		entryDn = entry.DN
		if len(*attrs) == 0 {
			glog.V(2).Infof("Entry DN = %s", entryDn)
		} else {
			for _, attr := range *attrs {
				values := entry.GetAttributeValues(attr)
				glog.V(2).Infof("Entry %s = %s", attr, strings.Join(values, "\n"))
				attributes[attr] = values
			}
		}
	}

	return entryDn, attributes, nil
}

func (la *LDAPAuth) getLabelAttributes() ([]string, error) {
	labelAttributes := make([]string, len(la.config.LabelMaps))
	i := 0
	for key, mapping := range la.config.LabelMaps {
		if mapping.Attribute == "" {
			return nil, fmt.Errorf("label %s is missing 'attribute' to map from", key)
		}
		labelAttributes[i] = mapping.Attribute
		i++
	}
	return labelAttributes, nil
}

func (la *LDAPAuth) getLabelsFromMap(attrMap map[string][]string) (map[string][]string, error) {
	labels := make(map[string][]string)
	for key, mapping := range la.config.LabelMaps {
		if mapping.Attribute == "" {
			return nil, fmt.Errorf("label %s is missing 'attribute' to map from", key)
		}

		mappingValues := attrMap[mapping.Attribute]
		if mappingValues != nil {
			if mapping.ParseCN {
				// shorten attribute to its common name
				for i, value := range mappingValues {
					cn := la.getCNFromDN(value)
					mappingValues[i] = cn
				}
			}
			labels[key] = mappingValues
		}
	}
	return labels, nil
}

func (la *LDAPAuth) getCNFromDN(dn string) string {
	parsedDN, err := ldap.ParseDN(dn)
	if err != nil {
		return ""
	}
	// Parsed DN result
	for _, rdn := range parsedDN.RDNs {
		for _, rdnAttr := range rdn.Attributes {
			if strings.ToUpper(rdnAttr.Type) == "CN" {
				return rdnAttr.Value
			}
		}
	}

	// else try using raw DN
	return dn
}

func (la *LDAPAuth) Stop() {
}

func (la *LDAPAuth) Name() string {
	return "LDAP"
}
