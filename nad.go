package nad

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"regexp"

	"golang.org/x/text/encoding/unicode"
	"gopkg.in/ldap.v3"
)

// VerifyDNPass returns nil on successful LDAP bind
func VerifyDNPass(dn, pass string) error {
	conn, err := dialLDAPTLS(dn, pass)
	if err != nil {
		return err
	}
	conn.Close()

	return nil
}

// VerifyCNPass returns an error if the password is invalid
func VerifyCNPass(bindDN, bindPass, cn, pass string) error {
	res, err := GetAttrs(bindDN, bindPass, cn, "dn")
	if err != nil {
		return fmt.Errorf("error finding user %s: %s", cn, err)
	}
	if len(res.Entries) != 1 {
		return fmt.Errorf("multiple or no results for sAMAccountname")
	}

	if err = VerifyDNPass(res.Entries[0].DN, pass); err != nil {
		return err
	}

	return nil
}

// ModPass uses bindDN to set "unicodePwd" attribute of targetDN to targetNewPass
// For use with admin or service accounts
func ModPass(bindDN, bindPass, targetDN, targetNewPass string) error {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	pwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", targetNewPass))
	if err != nil {
		return err
	}

	conn, err := dialLDAPTLS(bindDN, bindPass)
	if err != nil {
		return err
	}
	defer conn.Close()

	passReq := &ldap.ModifyRequest{
		DN: targetDN,
		Changes: []ldap.Change{
			{
				Operation: 2,
				Modification: ldap.PartialAttribute{
					Type: "unicodePwd",
					Vals: []string{pwdEncoded},
				},
			},
		},
	}

	err = conn.Modify(passReq)
	if err != nil {
		return err
	}

	return nil
}

// GetAttrs retrieves given attributes (such as "memberOf") for given sAMAccountName
func GetAttrs(bindDN, bindPass, sAMAccountName string, attributes ...string) (*ldap.SearchResult, error) {
	conn, err := dialLDAPTLS(bindDN, bindPass)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	re := regexp.MustCompile(`(?i)DC=[a-z]+,DC=[a-z]+$`)
	baseDN := re.FindString(bindDN)

	sreq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(sAMAccountName=%s))", sAMAccountName),
		attributes,
		nil,
	)

	return conn.Search(sreq)
}

// GetFilterAttrs does the same as GetAttrs but lets you give your own search filter
func GetFilterAttrs(bindDN, bindPass, filter string, attributes ...string) (*ldap.SearchResult, error) {
	conn, err := dialLDAPTLS(bindDN, bindPass)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	re := regexp.MustCompile(`(?i)DC=[a-z]+,DC=[a-z]+$`)
	baseDN := re.FindString(bindDN)

	sreq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	return conn.Search(sreq)
}

// dialLDAPTLS needs a truststore. Looks in the following locations (on linux); stops when finding one:
// "/etc/ssl/certs/ca-certificates.crt",
// "/etc/pki/tls/certs/ca-bundle.crt",
// "/etc/ssl/ca-bundle.pem",
// "/etc/pki/tls/cacert.pem",
// "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
// Incidentally this is where nais mounts NAV CA truststores
func dialLDAPTLS(bindDN, bindPass string) (*ldap.Conn, error) {
	domain, err := ParseDomain(bindDN)
	if err != nil {
		return nil, err
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		x509.NewCertPool()
	}

	ldapgwURL := "ldapgw." + domain + ":636"

	tc := &tls.Config{
		ServerName: "*." + domain,
		RootCAs:    rootCAs,
	}

	conn, err := ldap.DialTLS("tcp", ldapgwURL, tc)
	if err != nil {
		return nil, err
	}

	if err = conn.Bind(bindDN, bindPass); err != nil {
		return nil, err
	}

	return conn, nil
}

// ParseDomain takes a DN and returns the domain in the form of "domain.local"
func ParseDomain(dn string) (string, error) {
	re := regexp.MustCompile(`(?i)DC=([a-z]+),DC=([a-z]+)$`)
	xs := re.FindStringSubmatch(dn)
	if len(xs) != 3 {
		return "", fmt.Errorf("could not parse domain from %s", dn)
	}

	return fmt.Sprintf("%s.%s", xs[1], xs[2]), nil
}

// GetGroupMembers returns CN of users in given group
func GetGroupMembers(bindDN, bindPass, groupname string) ([]string, error) {
	baseDN := regexp.MustCompile(`(?i)DC=[a-z]+,DC=[a-z]+$`).FindString(bindDN)
	groupDN, err := GetGroupDN(bindDN, bindPass, groupname)
	if err != nil {
		return nil, err
	}
	conn, err := dialLDAPTLS(bindDN, bindPass)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	sr := newSearchRequest(baseDN,
		fmt.Sprintf("(&(objectCategory=user)(memberOf=%s))", groupDN),
		[]string{"CN"},
	)
	res, err := conn.Search(sr)
	if err != nil {
		return nil, err
	}
	members := []string{}
	for _, v := range res.Entries {
		members = append(members, v.Attributes[0].Values[0])
	}
	return members, nil
}

// GetGroupDN returns DN for given group CN
func GetGroupDN(bindDN, bindPass, cn string) (string, error) {
	conn, err := dialLDAPTLS(bindDN, bindPass)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	re := regexp.MustCompile(`(?i)DC=[a-z]+,DC=[a-z]+$`)
	baseDN := re.FindString(bindDN)

	sr := newSearchRequest(
		baseDN,
		fmt.Sprintf("(&(objectCategory=group)(cn=%s))", cn),
		[]string{},
	)

	res, err := conn.Search(sr)
	if err != nil {
		return "", err
	}
	if len(res.Entries) != 1 {
		return "", fmt.Errorf("multiple or no results for %s", cn)
	}

	return res.Entries[0].DN, err
}

func newSearchRequest(baseDN, filter string, attributes []string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)
}