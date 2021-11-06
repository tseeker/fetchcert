package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/sirupsen/logrus"
)

// Max supported CA chain length
const MAX_CA_CHAIN_LENGTH = 8

type (
	// Structure that describes the existing file for a certificate.
	tExistingFileInfo struct {
		owner uint32
		group uint32
		mode  os.FileMode
	}

	// Certificate building, including the configuration, LDAP connection,
	// and the array of chunks that's being built.
	tCertificateBuilder struct {
		config   *tCertificateFileConfig
		conn     *tLdapConn
		logger   *logrus.Entry
		data     [][]byte
		text     []byte
		existing *tExistingFileInfo
		changed  bool
	}
)

// Initialize a certificate file building using a LDAP connection and
// certificate file configuration.
func NewCertificateBuilder(conn *tLdapConn, config *tCertificateFileConfig) tCertificateBuilder {
	return tCertificateBuilder{
		config: config,
		conn:   conn,
		logger: log.WithField("file", config.Path),
		data:   make([][]byte, 0),
	}
}

// Build the certificate file's data, returning any error that occurs while
// reading the source data.
func (b *tCertificateBuilder) Build() error {
	b.logger.Debug("Checking for updates")
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
	b.generateText()
	return nil
}

// Check whether the data should be written to disk.
func (b *tCertificateBuilder) MustWrite() bool {
	info, err := os.Lstat(b.config.Path)
	if err != nil {
		return true
	}

	sys_stat := info.Sys().(*syscall.Stat_t)
	eif := &tExistingFileInfo{}
	eif.mode = info.Mode()
	eif.owner = sys_stat.Uid
	eif.group = sys_stat.Gid
	b.existing = eif

	if sys_stat.Size != int64(len(b.text)) {
		return true
	}
	existing, err := ioutil.ReadFile(b.config.Path)
	if err != nil {
		return true
	}
	for i, ch := range b.text {
		if ch != existing[i] {
			return true
		}
	}
	return false
}

// Write the file's data
func (b *tCertificateBuilder) WriteFile() error {
	log.WithField("file", b.config.Path).Info("Writing certificate data to file")
	err := ioutil.WriteFile(b.config.Path, b.text, b.config.Mode)
	if err == nil {
		b.changed = true
	}
	return err
}

// Update the file's owner and group
func (b *tCertificateBuilder) UpdatePrivileges() error {
	update_mode := !b.changed && b.existing.mode != b.config.Mode
	if update_mode {
		err := os.Chmod(b.config.Path, b.config.Mode)
		if err != nil {
			return err
		}
	}

	log := b.logger
	set_uid, set_gid := -1, -1
	if b.config.Owner != "" {
		usr, err := user.Lookup(b.config.Owner)
		if err != nil {
			return err
		}
		uid, err := strconv.Atoi(usr.Uid)
		if b.changed || b.existing == nil || b.existing.owner != uint32(uid) {
			set_uid = uid
			log = log.WithField("uid", set_uid)
		}
	}
	if b.config.Group != "" {
		group, err := user.LookupGroup(b.config.Group)
		if err != nil {
			return err
		}
		gid, err := strconv.Atoi(group.Gid)
		if b.changed || b.existing == nil || b.existing.group != uint32(gid) {
			set_gid = gid
			log = log.WithField("gid", set_gid)
		}
	}
	if set_gid != -1 || set_uid != -1 {
		log.Info("Updating file owner/group")
		err := os.Chown(b.config.Path, set_uid, set_gid)
		if err == nil {
			b.changed = true
		}
		return err
	} else {
		b.changed = b.changed || update_mode
		log.Debug("No update to privileges")
		return nil
	}
}

// Append PEM files from a list.
func (b *tCertificateBuilder) appendPemFiles(files []string) error {
	for _, path := range files {
		var err error
		b.logger.WithField("source", path).Debug("Adding PEM file")
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
		dn := b.conn.BaseDN()
		if dn != "" {
			dn = "," + dn
		}
		dn = b.config.Certificate + dn
		b.logger.WithField("dn", dn).Debug("Adding EE certificate from LDAP")
		data, err := b.conn.GetEndEntityCertificate(dn)
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
	bdn := b.conn.BaseDN()
	if bdn != "" {
		bdn = "," + bdn
	}
	for _, dn := range b.config.CACertificates {
		b.logger.WithField("dn", dn+bdn).Debug("Adding CA certificate from LDAP")
		data, _, err := b.conn.GetCaCertificate(dn + bdn)
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
	if b.conn.BaseDN() != "" {
		dn = dn + "," + b.conn.BaseDN()
	}
	for {
		data, nextDn, err := b.conn.GetCaCertificate(dn)
		if err != nil {
			return err
		}
		if nFound != 0 {
			if data == nil {
				return fmt.Errorf("No CA certificate at DN '%s'", dn)
			}
			b.logger.WithField("dn", dn).Debug("Adding CA certificate from LDAP chain")
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
	b.logger.Debug("Reversing PEM list")
	l := len(b.data) / 2
	for i := 0; i < l/2; i++ {
		j := l - i - 1
		b.data[i], b.data[j] = b.data[j], b.data[i]
	}
}

// Generate the final text of the file
func (b *tCertificateBuilder) generateText() {
	size := int64(0)
	for i := range b.data {
		size += int64(len(b.data[i]))
		if i != 0 && b.data[i-1][len(b.data[i-1])-1] != '\n' {
			size++
		}
	}
	b.text = make([]byte, size)
	pos := 0
	for i := range b.data {
		copied := copy(b.text[pos:], b.data[i])
		pos += copied
		if i != 0 && b.data[i-1][len(b.data[i-1])-1] != '\n' {
			b.text[pos] = '\n'
			pos++
		}
	}
	b.logger.WithField("size", size).Debug("Data generated")
}
