package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// Max supported CA chain length
const MAX_CA_CHAIN_LENGTH = 8

type (
	// Certificate building, including the configuration, LDAP connection,
	// and the array of chunks that's being built.
	tCertificateBuilder struct {
		config *tCertificateFileConfig
		conn   *tLdapConn
		data   [][]byte
	}
)

// Initialize a certificate file building using a LDAP connection and
// certificate file configuration.
func NewCertificateBuilder(conn *tLdapConn, config *tCertificateFileConfig) tCertificateBuilder {
	return tCertificateBuilder{
		config: config,
		conn:   conn,
		data:   make([][]byte, 0),
	}
}

// Build the certificate file's data, returning any error that occurs while
// reading the source data.
func (b *tCertificateBuilder) Build() error {
	err := b.appendPemFiles(b.config.PrependFiles)
	if err != nil {
		return err
	}
	err = b.appendCertificate()
	if err != nil {
		return err
	}
	err = b.appendCaCertificates()
	if err != nil {
		return err
	}
	err = b.appendPemFiles(b.config.AppendFiles)
	if err != nil {
		return err
	}
	if b.config.Reverse {
		b.reverseChunks()
	}
	return nil
}

// Append PEM files from a list.
func (b *tCertificateBuilder) appendPemFiles(files []string) error {
	for _, path := range files {
		var err error
		err = b.appendPem(path)
		if err != nil {
			return err
		}
	}
	return nil
}

// Append a PEM file to the current list of data chunks
func (b *tCertificateBuilder) appendPem(input string) error {
	data, err := ioutil.ReadFile(input)
	if err != nil {
		return fmt.Errorf("Could not load '%s': %w", input, err)
	}
	rest := data
	hadBlock := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		hadBlock = true
		b.data = append(b.data, pem.EncodeToMemory(block))
	}
	if hadBlock {
		return nil
	} else {
		return fmt.Errorf("No PEM blocks found in '%s'", input)
	}
}

// Append the main, end-entity certificate from the LDAP
func (b *tCertificateBuilder) appendCertificate() error {
	if b.config.Certificate != "" {
		dn := b.conn.Config.Structure.BaseDN
		if dn != "" {
			dn = "," + dn
		}
		dn = b.config.Certificate + dn
		data, err := b.conn.getEndEntityCertificate(dn)
		if err != nil {
			return err
		}
		b.data = append(b.data, data)
	}
	return nil
}

// Append all CA certificates, reading the list from the LDAP or from the
// configuration.
func (b *tCertificateBuilder) appendCaCertificates() error {
	if len(b.config.CACertificates) != 0 {
		return b.appendListedCaCerts()
	} else if b.config.CAChainOf != "" {
		return b.appendChainedCaCerts()
	} else {
		return nil
	}
}

// Append CA certificates based on a list of DNs
func (b *tCertificateBuilder) appendListedCaCerts() error {
	bdn := b.conn.Config.Structure.BaseDN
	if bdn != "" {
		bdn = "," + bdn
	}
	for _, dn := range b.config.CACertificates {
		data, _, err := b.conn.getCaCertificate(dn + bdn)
		if err != nil {
			return err
		}
		if data == nil {
			return fmt.Errorf("No CA certificate at DN '%s'", dn)
		}
		b.data = append(b.data, data)
	}
	return nil
}

// Append CA certificates by following a chain starting at some DN
func (b *tCertificateBuilder) appendChainedCaCerts() error {
	nFound := 0
	dn := b.config.CAChainOf
	if b.conn.Config.Structure.BaseDN != "" {
		dn = dn + "," + b.conn.Config.Structure.BaseDN
	}
	for {
		data, nextDn, err := b.conn.getCaCertificate(dn)
		if err != nil {
			return err
		}
		if nFound != 0 {
			if data == nil {
				return fmt.Errorf("No CA certificate at DN '%s'", dn)
			}
			b.data = append(b.data, data)
		}
		if nextDn == "" {
			return nil
		}
		dn = nextDn
		nFound += 1
		if nFound == MAX_CA_CHAIN_LENGTH {
			return fmt.Errorf("DN '%s': CA chain length exceeded", dn)
		}
	}
}

// Reverse the chunks in the list
func (b *tCertificateBuilder) reverseChunks() {
	l := len(b.data) / 2
	for i := 0; i < l/2; i++ {
		j := l - i - 1
		b.data[i], b.data[j] = b.data[j], b.data[i]
	}
}
