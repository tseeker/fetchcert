package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"
)

type (
	// LDAP connection encapsulation. This includes the connection itself, as well as a logger
	// that includes fields related to the LDAP server and a copy of the initial configuration.
	tLdapConn struct {
		Config  tLdapConfig
		conn    *ldap.Conn
		log     *logrus.Entry
		server  int
		counter uint
	}

	// LDAP group members
	ldapGroupMembers map[string][]string
)

// Try to establish a connection to one of the servers
func getLdapConnection(cfg tLdapConfig) *tLdapConn {
	for i := range cfg.Servers {
		conn := getLdapServerConnection(cfg, i)
		if conn != nil {
			return conn
		}
	}
	return nil
}

// Establish a connection to a LDAP server
func getLdapServerConnection(cfg tLdapConfig, server int) *tLdapConn {
	if server < 0 || server >= len(cfg.Servers) {
		logrus.Panic("Invalid server index %d", server)
	}

	scfg := cfg.Servers[server]
	dest := fmt.Sprintf("%s:%d", scfg.Host, scfg.Port)
	log := log.WithFields(logrus.Fields{
		"ldap_server": dest,
		"ldap_tls":    scfg.TLS,
	})
	log.Trace("Establishing LDAP connection")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: scfg.TLSNoVerify,
	}
	if scfg.TLS != "no" && scfg.CaChain != "" {
		log := log.WithField("cachain", scfg.CaChain)
		data, err := ioutil.ReadFile(scfg.CaChain)
		if err != nil {
			log.WithField("error", err).Error("Failed to read CA certificate chain")
			return nil
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			log.Error("Could not add CA certificates")
			return nil
		}
		tlsConfig.RootCAs = pool
	}

	var err error
	var lc *ldap.Conn
	if scfg.TLS == "yes" {
		lc, err = ldap.DialTLS("tcp", dest, tlsConfig)
	} else {
		lc, err = ldap.Dial("tcp", dest)
	}
	if err != nil {
		log.WithField("error", err).Error("Failed to connect to the LDAP server")
		return nil
	}

	if scfg.TLS == "starttls" {
		err = lc.StartTLS(tlsConfig)
		if err != nil {
			lc.Close()
			log.WithField("error", err).Error("StartTLS failed")
			return nil
		}
	}

	if scfg.BindUser != "" {
		log = log.WithField("ldap_user", scfg.BindUser)
		err := lc.Bind(scfg.BindUser, scfg.BindPassword)
		if err != nil {
			lc.Close()
			log.WithField("error", err).Error("Could not bind")
			return nil
		}
	}
	log.Debug("LDAP connection established")
	return &tLdapConn{
		Config: cfg,
		conn:   lc,
		log:    log,
		server: server,
	}
}

// Run a LDAP query to obtain a single object.
func (conn *tLdapConn) getObject(dn string, attrs []string) (bool, *ldap.Entry) {
	log := conn.log.WithFields(logrus.Fields{
		"dn":         dn,
		"attributes": attrs,
	})
	log.Trace("Accessing DN")
	conn.counter++
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", attrs, nil)
	res, err := conn.conn.Search(req)
	if err != nil {
		log := log.WithField("error", err)
		ldapError, ok := err.(*ldap.Error)
		if ok {
			log = log.WithFields(logrus.Fields{
				"ldap_result":  ldapError.ResultCode,
				"ldap_message": ldapError.Error(),
			})
		}
		log.Error("LDAP query failed")
		return false, nil
	}
	if len(res.Entries) > 1 {
		log.WithField("results", len(res.Entries)).
			Warning("LDAP search returned more than 1 record")
		return false, nil
	}
	log.Trace("Obtained LDAP object")
	return true, res.Entries[0]
}

// Close a LDAP connection
func (conn *tLdapConn) close() {
	conn.log.WithField("queries", conn.counter).Debug("Closing LDAP connection")
	conn.conn.Close()
}

// Get an end entity's certificate from the LDAP
func (conn *tLdapConn) getEndEntityCertificate(dn string) ([]byte, error) {
	eec := conn.Config.Structure.EndEntityCertificate
	success, entry := conn.getObject(dn, []string{eec})
	if !success {
		return nil, fmt.Errorf("Could not read certificate from '%s'", dn)
	}
	values := entry.GetRawAttributeValues(eec)
	nFound := len(values)
	if nFound != 1 {
		return nil, fmt.Errorf("DN %s - one value expected for %s, %d values found", dn, eec, nFound)
	}
	_, err := x509.ParseCertificate(values[0])
	if err != nil {
		return nil, fmt.Errorf("DN %s - invalid certificate in attribute %s : %w", dn, eec, err)
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: values[0],
	})
	return data, nil
}

// Get a CA certificate, as well as the value of the chaining field, from
// the LDAP.
func (conn *tLdapConn) getCaCertificate(dn string) ([]byte, string, error) {
	cc := conn.Config.Structure.CACertificate
	chain := conn.Config.Structure.CAChaining
	attrs := []string{cc}
	if chain != "" {
		attrs = append(attrs, chain)
	}

	success, entry := conn.getObject(dn, attrs)
	if !success {
		return nil, "", fmt.Errorf("Could not read certificate from '%s'", dn)
	}

	var ca_cert []byte = nil
	var chain_dn string = ""

	values := entry.GetRawAttributeValues(cc)
	nFound := len(values)
	if nFound > 1 {
		return ca_cert, chain_dn, fmt.Errorf("DN %s - one value expected for %s, %d values found", dn, cc, nFound)
	} else if nFound == 1 {
		_, err := x509.ParseCertificate(values[0])
		if err != nil {
			return nil, "", fmt.Errorf("DN %s - invalid certificate in attribute %s : %w", dn, cc, err)
		}
		ca_cert = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: values[0],
		})
	}

	chval := entry.GetAttributeValues(chain)
	nFound = len(chval)
	if nFound > 1 {
		return ca_cert, chain_dn, fmt.Errorf("DN %s - one value expected for %s, %d values found", dn, chain, nFound)
	} else if nFound == 1 {
		chain_dn = chval[0]
	}

	return ca_cert, chain_dn, nil
}
