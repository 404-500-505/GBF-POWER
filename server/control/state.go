package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var errUnavailable = errors.New("unavailable")

// authorizedKeys is deliberately independent of OpenStore: sshd must consult
// only committed state, and a lookup must never create, repair or export files.
func authorizedKeys(dir string) ([]byte, error) {
	db, e := readDatabase(dir)
	if e != nil {
		return nil, errUnavailable
	}
	return activeKeys(db), nil
}

func readDatabase(dir string) (database, error) {
	f, e := os.Open(filepath.Join(dir, "state.json"))
	if e != nil {
		return database{}, e
	}
	defer f.Close()
	const maximum = 64 << 20
	b, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil || len(b) > maximum {
		return database{}, errUnavailable
	}
	return parseDatabase(b)
}

// Both daemon startup and the sshd lookup use the same strict schema. Missing
// security flags must never become false when a later mutation saves the DB.
func parseDatabase(b []byte) (database, error) {
	var db *struct {
		Licenses []struct {
			License
			Disabled *bool `json:"disabled"`
		} `json:"licenses"`
		Devices []struct {
			Device
			Revoked *bool `json:"revoked"`
		} `json:"devices"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&db) != nil || db == nil || db.Licenses == nil || db.Devices == nil {
		return database{}, errUnavailable
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return database{}, errUnavailable
	}
	validHex := func(value string, n int) bool {
		raw, e := hex.DecodeString(value)
		return e == nil && len(raw) == n && hex.EncodeToString(raw) == value
	}
	licenses := map[string]bool{}
	hashes := map[string]bool{}
	out := database{Licenses: []License{}, Devices: []Device{}}
	for _, l := range db.Licenses {
		if !validHex(l.ID, 12) || !validHex(l.CodeHash, 32) || l.Created <= 0 || l.Disabled == nil {
			return database{}, errUnavailable
		}
		if _, exists := licenses[l.ID]; exists || hashes[l.CodeHash] {
			return database{}, errUnavailable
		}
		licenses[l.ID] = !*l.Disabled
		hashes[l.CodeHash] = true
		l.License.Disabled = *l.Disabled
		out.Licenses = append(out.Licenses, l.License)
	}
	ids := map[string]bool{}
	pubs := map[string]bool{}
	counts := map[string]int{}
	for _, device := range db.Devices {
		_, exists := licenses[device.LicenseID]
		_, validPub := parsePublicKey(device.PublicKey)
		if !exists || !validHex(device.ID, 12) || !validPub || device.Created <= 0 || device.Revoked == nil || ids[device.ID] || pubs[device.PublicKey] {
			return database{}, errUnavailable
		}
		ids[device.ID] = true
		pubs[device.PublicKey] = true
		if !*device.Revoked {
			counts[device.LicenseID]++
			if counts[device.LicenseID] > 2 {
				return database{}, errUnavailable
			}
		}
		device.Device.Revoked = *device.Revoked
		out.Devices = append(out.Devices, device.Device)
	}
	return out, nil
}

func activeKeys(db database) []byte {
	active := map[string]bool{}
	for _, l := range db.Licenses {
		active[l.ID] = !l.Disabled
	}
	keys := []string{}
	for _, d := range db.Devices {
		if !d.Revoked && active[d.LicenseID] {
			keys = append(keys, "restrict,port-forwarding "+d.PublicKey)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(keys, "\n") + "\n")
}

type License struct {
	ID       string `json:"id"`
	CodeHash string `json:"code_hash"`
	Disabled bool   `json:"disabled"`
	Created  int64  `json:"created"`
}
type Device struct {
	ID        string `json:"id"`
	LicenseID string `json:"license_id"`
	PublicKey string `json:"public_key"`
	Revoked   bool   `json:"revoked"`
	Created   int64  `json:"created"`
}
type database struct {
	Licenses []License `json:"licenses"`
	Devices  []Device  `json:"devices"`
}
type Store struct {
	mu       sync.Mutex
	dir      string
	db       database
	dirty    bool
	syncDir  func(string) error
	ops      *Operations
	onChange func(database)
	nodes    *NodeSelector
}

func (s *Store) AttachNodeSelector(selector *NodeSelector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes = selector
}

func OpenStore(dir string) (*Store, error) {
	db, e := readDatabase(dir)
	if e != nil {
		if !os.IsNotExist(e) {
			return nil, e
		}
		db = database{Licenses: []License{}, Devices: []Device{}}
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if e := os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	s := &Store{dir: dir, db: db, syncDir: syncDirectory}
	s.ops = openOperations(dir)
	if e = s.export(); e != nil {
		return nil, e
	}
	return s, nil
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func codeHash(code string) string { h := sha256.Sum256([]byte(code)); return hex.EncodeToString(h[:]) }

// The committed result distinguishes an atomic replacement from its durability.
// After rename succeeds, callers must retain the new state even if fsync fails.
func atomicWrite(path string, b []byte, syncDir func(string) error) (committed bool, err error) {
	f, e := os.CreateTemp(filepath.Dir(path), ".commit-*")
	if e != nil {
		return false, e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return false, e
	}
	if e = os.Rename(tmp, path); e != nil {
		return false, e
	}
	return true, syncDir(filepath.Dir(path))
}
func (s *Store) save(next database) error {
	b, e := json.MarshalIndent(next, "", "  ")
	if e != nil {
		return errUnavailable
	}
	committed, e := atomicWrite(filepath.Join(s.dir, "state.json"), b, s.syncDir)
	if committed {
		s.db = next
		if s.onChange != nil {
			s.onChange(next)
		}
	}
	if e != nil {
		if committed {
			s.dirty = true
		}
		return errUnavailable
	}
	return s.export()
}
func (s *Store) clone() database {
	return database{Licenses: append([]License{}, s.db.Licenses...), Devices: append([]Device{}, s.db.Devices...)}
}
func (s *Store) export() error {
	path := filepath.Join(s.dir, "authorized_keys")
	if _, e := atomicWrite(path, activeKeys(s.db), s.syncDir); e != nil {
		s.dirty = true
		_ = os.Remove(path)
		return errUnavailable
	}
	s.dirty = false
	return nil
}

func (s *Store) Reconcile() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		return s.export()
	}
	return nil
}
func (s *Store) Create() (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, e := randomHex(16)
	if e != nil {
		return "", "", errUnavailable
	}
	id, e := randomHex(12)
	if e != nil {
		return "", "", errUnavailable
	}
	code := "GBF-" + strings.ToUpper(raw)
	next := s.clone()
	next.Licenses = append(next.Licenses, License{ID: id, CodeHash: codeHash(code), Created: time.Now().Unix()})
	if e = s.save(next); e != nil {
		return "", "", e
	}
	return id, code, nil
}
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.clone()
	for i := range next.Devices {
		if next.Devices[i].ID == id {
			next.Devices[i].Revoked = true
			return s.save(next)
		}
	}
	return errors.New("invalid_request")
}
func (s *Store) Disable(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.clone()
	for i := range next.Licenses {
		if next.Licenses[i].ID == id {
			next.Licenses[i].Disabled = true
			return s.save(next)
		}
	}
	return errors.New("invalid_request")
}

type LicenseSummary struct {
	ID          string          `json:"id"`
	Disabled    bool            `json:"disabled"`
	Created     int64           `json:"created"`
	DeviceCount int             `json:"device_count"`
	Devices     []DeviceSummary `json:"devices"`
}
type DeviceSummary struct {
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
	Created int64  `json:"created"`
}

func (s *Store) List() []LicenseSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []LicenseSummary{}
	for _, l := range s.db.Licenses {
		row := LicenseSummary{ID: l.ID, Disabled: l.Disabled, Created: l.Created, Devices: []DeviceSummary{}}
		for _, d := range s.db.Devices {
			if d.LicenseID == l.ID {
				row.Devices = append(row.Devices, DeviceSummary{d.ID, d.Revoked, d.Created})
				if !d.Revoked {
					row.DeviceCount++
				}
			}
		}
		out = append(out, row)
	}
	return out
}
func (s *Store) access(code, pub string, activate bool) (Device, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		if e := s.export(); e != nil {
			return Device{}, 0, e
		}
	}
	var license *License
	var existing *Device
	for i := range s.db.Devices {
		if s.db.Devices[i].PublicKey == pub {
			existing = &s.db.Devices[i]
			break
		}
	}
	if activate {
		h := codeHash(code)
		for i := range s.db.Licenses {
			if s.db.Licenses[i].CodeHash == h {
				license = &s.db.Licenses[i]
				break
			}
		}
		if license == nil {
			return Device{}, 0, errors.New("invalid_code")
		}
	} else if existing != nil {
		for i := range s.db.Licenses {
			if s.db.Licenses[i].ID == existing.LicenseID {
				license = &s.db.Licenses[i]
				break
			}
		}
	}
	if license == nil || license.Disabled {
		return Device{}, 0, errors.New("revoked")
	}
	if existing != nil && existing.Revoked {
		return Device{}, 0, errors.New("revoked")
	}
	// Disabling a license revokes that entitlement, not the device credential.
	// Only an explicit activation with a new valid code may move an inactive
	// binding. Explicit device revocation remains a separate global denial.
	moving := existing != nil && existing.LicenseID != license.ID
	if moving {
		oldDisabled := false
		for _, old := range s.db.Licenses {
			if old.ID == existing.LicenseID {
				oldDisabled = old.Disabled
				break
			}
		}
		if !activate || !oldDisabled {
			return Device{}, 0, errors.New("revoked")
		}
	}
	count := 0
	for _, d := range s.db.Devices {
		if d.LicenseID == license.ID && !d.Revoked {
			count++
		}
	}
	if existing != nil {
		if moving {
			if count >= 2 {
				return Device{}, 0, errors.New("device_limit")
			}
			next := s.clone()
			moved := *existing
			moved.LicenseID = license.ID
			for i := range next.Devices {
				if next.Devices[i].ID == moved.ID {
					next.Devices[i] = moved
					break
				}
			}
			if e := s.save(next); e != nil {
				return Device{}, 0, e
			}
			return moved, count + 1, nil
		}
		if e := s.export(); e != nil {
			return Device{}, 0, e
		}
		return *existing, count, nil
	}
	if !activate {
		return Device{}, 0, errors.New("revoked")
	}
	if count >= 2 {
		return Device{}, 0, errors.New("device_limit")
	}
	id, e := randomHex(12)
	if e != nil {
		return Device{}, 0, errUnavailable
	}
	d := Device{ID: id, LicenseID: license.ID, PublicKey: pub, Created: time.Now().Unix()}
	next := s.clone()
	next.Devices = append(next.Devices, d)
	if e = s.save(next); e != nil {
		return Device{}, 0, e
	}
	return d, count + 1, nil
}
