package nad

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"golang.org/x/text/encoding/unicode"
	"gopkg.in/ldap.v3"
)

type domain string

// PROD, PREPROD, and TEST represents NAVs AD domains
const (
	PROD    domain = "adeo.no"
	PREPROD domain = "preprod.local"
	TEST    domain = "test.local"
)

// VerifyDNPass returns nil on successful LDAP bind
func VerifyDNPass(dn, pass string, e domain) error {
	conn, err := dialLDAPTLS(dn, pass, e)
	if err != nil {
		return err
	}
	conn.Close()

	return nil
}

// ModPass uses bindDN to set "unicodePwd" attribute of targetDN to targetNewPass
// For use with admin or service accounts
func ModPass(bindDN, bindPass, targetDN, targetNewPass string, domain domain) error {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	pwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", targetNewPass))
	if err != nil {
		return err
	}

	conn, err := dialLDAPTLS(bindDN, bindPass, domain)
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
func GetAttrs(bindDN, bindPass, sAMAccountName string, domain domain, attributes ...string) (*ldap.SearchResult, error) {
	conn, err := dialLDAPTLS(bindDN, bindPass, domain)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	baseDN := "DC=" + strings.Replace(string(domain), ".", ",DC=", 1)

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

// dialLDAPTLS needs a truststore. Looks in the following locations (on linux); stops when finding one:
// "/etc/ssl/certs/ca-certificates.crt",
// "/etc/pki/tls/certs/ca-bundle.crt",
// "/etc/ssl/ca-bundle.pem",
// "/etc/pki/tls/cacert.pem",
// "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
// Incidentally this is where nais mounts NAV CA truststores
func dialLDAPTLS(bindDN, bindPass string, domain domain) (*ldap.Conn, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		x509.NewCertPool()
	}

	ldapgwURL := "ldapgw." + string(domain) + ":636"
	tc := &tls.Config{
		ServerName: "*." + string(domain),
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
