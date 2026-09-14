package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)
var shanghai = time.FixedZone("Asia/Shanghai", 8*60*60)

type Traffic struct {
	Upload   uint64 `json:"upload_bytes"`
	Download uint64 `json:"download_bytes"`
}
type DeviceOps struct {
	Note     string `json:"note"`
	LastSeen int64  `json:"last_seen"`
	Traffic
	Days map[string]Traffic `json:"days"`
}
type Event struct {
	Time   int64  `json:"time"`
	Action string `json:"action"`
	Target string `json:"target"`
}
type opsDatabase struct {
	Version       int                   `json:"version"`
	Licenses      map[string]string     `json:"licenses"`
	Devices       map[string]*DeviceOps `json:"devices"`
	Events        []Event               `json:"events"`
	LastPersisted int64                 `json:"last_persisted_at"`
}
type liveTraffic struct {
	Active      int
	Online      int
	Previous    Traffic
	UploadBPS   *float64
	DownloadBPS *float64
}
type Operations struct {
	mu         sync.Mutex
	dir        string
	db         opsDatabase
	live       map[string]*liveTraffic
	enabled    bool
	listen     string
	healthy    bool
	problem    string
	lastSample time.Time
	started    time.Time
	stats      systemSampler
	syncDir    func(string) error
}
type MeteringHealth struct {
	Enabled       bool   `json:"enabled"`
	Listen        string `json:"listen"`
	Healthy       bool   `json:"healthy"`
	LastPersisted int64  `json:"last_persisted_at"`
	Error         string `json:"error"`
}
type OpsDevice struct {
	ID             string `json:"id"`
	Revoked        bool   `json:"revoked"`
	Created        int64  `json:"created"`
	Fingerprint    string `json:"fingerprint"`
	Note           string `json:"note"`
	LastSeen       int64  `json:"last_seen"`
	Active         int    `json:"active_connections"`
	OnlineSessions int    `json:"online_sessions"`
	Traffic
	TodayUpload   uint64   `json:"today_upload_bytes"`
	TodayDownload uint64   `json:"today_download_bytes"`
	UploadBPS     *float64 `json:"upload_bps"`
	DownloadBPS   *float64 `json:"download_bps"`
}
type OpsLicense struct {
	ID          string      `json:"id"`
	Disabled    bool        `json:"disabled"`
	Created     int64       `json:"created"`
	DeviceCount int         `json:"device_count"`
	Note        string      `json:"note"`
	Devices     []OpsDevice `json:"devices"`
}
type Snapshot struct {
	SampledAt int64          `json:"sampled_at"`
	Server    ServerStats    `json:"server"`
	Licenses  []OpsLicense   `json:"licenses"`
	Metering  MeteringHealth `json:"metering"`
	Events    []Event        `json:"events"`
	Nodes     []NodeStatus   `json:"nodes"`
}

func openOperations(dir string) *Operations {
	o := &Operations{dir: dir, healthy: true, started: time.Now(), live: map[string]*liveTraffic{}, syncDir: syncDirectory,
		db: opsDatabase{Version: 1, Licenses: map[string]string{}, Devices: map[string]*DeviceOps{}, Events: []Event{}}}
	f, e := os.Open(filepath.Join(dir, "ops.json"))
	if os.IsNotExist(e) {
		return o
	}
	if e != nil {
		o.unhealthyLocked("cannot read operations data")
		return o
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if e != nil || len(b) > 64<<20 {
		o.unhealthyLocked("invalid operations data")
		return o
	}
	var db opsDatabase
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&db) != nil || d.Decode(&extra) != io.EOF || !validOps(db) {
		o.unhealthyLocked("invalid operations data")
		return o
	}
	o.db = db
	return o
}
func validNote(s string) bool { return utf8.ValidString(s) && utf8.RuneCountInString(s) <= 500 }
func validOps(db opsDatabase) bool {
	if db.Version != 1 || db.Licenses == nil || db.Devices == nil || db.Events == nil || len(db.Events) > 1000 || db.LastPersisted < 0 {
		return false
	}
	for id, note := range db.Licenses {
		if !idPattern.MatchString(id) || !validNote(note) {
			return false
		}
	}
	for id, d := range db.Devices {
		if !idPattern.MatchString(id) || d == nil || !validNote(d.Note) || d.LastSeen < 0 || d.Days == nil {
			return false
		}
		var up, down uint64
		for day, v := range d.Days {
			if _, e := time.Parse("2006-01-02", day); e != nil {
				return false
			}
			if ^uint64(0)-up < v.Upload || ^uint64(0)-down < v.Download {
				return false
			}
			up += v.Upload
			down += v.Download
		}
		if up > d.Upload || down > d.Download {
			return false
		}
	}
	for _, e := range db.Events {
		if e.Time <= 0 || !idPattern.MatchString(e.Target) {
			return false
		}
		switch e.Action {
		case "create", "revoke-device", "disable-code", "note-license", "note-device":
		default:
			return false
		}
	}
	return true
}
func (o *Operations) unhealthyLocked(reason string) { o.healthy = false; o.problem = reason }
func (o *Operations) Healthy() bool                 { o.mu.Lock(); defer o.mu.Unlock(); return o.healthy }
func (o *Operations) deviceLocked(id string) (*DeviceOps, *liveTraffic) {
	d := o.db.Devices[id]
	if d == nil {
		d = &DeviceOps{Days: map[string]Traffic{}}
		o.db.Devices[id] = d
	}
	l := o.live[id]
	if l == nil {
		l = &liveTraffic{Previous: d.Traffic}
		o.live[id] = l
	}
	return d, l
}
func (o *Operations) Add(id string, upload bool, n int) {
	if n <= 0 {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	d, _ := o.deviceLocked(id)
	day := time.Now().In(shanghai).Format("2006-01-02")
	v := d.Days[day]
	count := uint64(n)
	if upload {
		if ^uint64(0)-d.Upload < count {
			o.unhealthyLocked("traffic counter overflow")
			return
		}
		d.Upload += count
		v.Upload += count
	} else {
		if ^uint64(0)-d.Download < count {
			o.unhealthyLocked("traffic counter overflow")
			return
		}
		d.Download += count
		v.Download += count
	}
	d.Days[day] = v
}
func (o *Operations) Connection(id string, delta int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	d, l := o.deviceLocked(id)
	l.Active += delta
	if delta > 0 {
		d.LastSeen = time.Now().Unix()
	}
}
func (o *Operations) Session(id string, delta int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	d, l := o.deviceLocked(id)
	l.Online += delta
	if l.Online < 0 {
		l.Online = 0
	}
	if delta > 0 {
		d.LastSeen = time.Now().Unix()
	}
}
func (o *Operations) Sample(now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	elapsed := now.Sub(o.lastSample).Seconds()
	for id, d := range o.db.Devices {
		_, l := o.deviceLocked(id)
		if !o.lastSample.IsZero() && elapsed > 0 {
			up := float64(d.Upload-l.Previous.Upload) / elapsed
			down := float64(d.Download-l.Previous.Download) / elapsed
			l.UploadBPS = &up
			l.DownloadBPS = &down
		}
		l.Previous = d.Traffic
	}
	o.lastSample = now
}
func (o *Operations) flushLocked() error {
	if !o.healthy {
		return errUnavailable
	}
	cutoff := time.Now().In(shanghai).AddDate(0, 0, -30).Format("2006-01-02")
	for _, d := range o.db.Devices {
		for day := range d.Days {
			if day < cutoff {
				delete(d.Days, day)
			}
		}
	}
	previous := o.db.LastPersisted
	o.db.LastPersisted = time.Now().Unix()
	b, e := json.MarshalIndent(o.db, "", "  ")
	if e == nil {
		_, e = atomicWrite(filepath.Join(o.dir, "ops.json"), b, o.syncDir)
	}
	if e != nil {
		o.db.LastPersisted = previous
		o.unhealthyLocked("cannot persist operations data")
		return errUnavailable
	}
	return nil
}
func (o *Operations) Flush() error { o.mu.Lock(); defer o.mu.Unlock(); return o.flushLocked() }
func (o *Operations) eventLocked(action, id string) {
	o.db.Events = append(o.db.Events, Event{time.Now().Unix(), action, id})
	if len(o.db.Events) > 1000 {
		o.db.Events = append([]Event{}, o.db.Events[len(o.db.Events)-1000:]...)
	}
}
func (o *Operations) Event(action, id string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.healthy {
		return errUnavailable
	}
	o.eventLocked(action, id)
	return o.flushLocked()
}
func (s *Store) Note(id, note string, license bool) error {
	if !idPattern.MatchString(id) || !validNote(note) {
		return errors.New("invalid_request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	if license {
		for _, l := range s.db.Licenses {
			if l.ID == id {
				found = true
				break
			}
		}
	} else {
		for _, d := range s.db.Devices {
			if d.ID == id {
				found = true
				break
			}
		}
	}
	if !found {
		return errors.New("invalid_request")
	}
	o := s.ops
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.healthy {
		return errUnavailable
	}
	action := "note-device"
	if license {
		o.db.Licenses[id] = note
		action = "note-license"
	} else {
		d, _ := o.deviceLocked(id)
		d.Note = note
	}
	o.eventLocked(action, id)
	return o.flushLocked()
}
func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	db := s.clone()
	nodeSelector := s.nodes
	s.mu.Unlock()
	o := s.ops
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	out := Snapshot{SampledAt: now.Unix(), Server: o.stats.Sample(o.dir, now.Sub(o.started).Seconds()), Licenses: []OpsLicense{}, Metering: MeteringHealth{o.enabled, o.listen, o.healthy, o.db.LastPersisted, o.problem}, Events: append([]Event{}, o.db.Events...), Nodes: []NodeStatus{}}
	if nodeSelector != nil {
		out.Nodes = nodeSelector.Snapshot(now)
	}
	type remoteDevice struct {
		online, active int
		lastSeen       int64
		uploadBPS      uint64
		downloadBPS    uint64
		seen           bool
	}
	remote := map[string]remoteDevice{}
	for _, node := range out.Nodes {
		if node.ID == "tokyo" || !node.Healthy {
			continue
		}
		for _, device := range node.DeviceStates {
			value := remote[device.ID]
			value.online += device.OnlineSessions
			value.active += device.ActiveConnections
			if device.LastSeen > value.lastSeen {
				value.lastSeen = device.LastSeen
			}
			value.uploadBPS += device.UploadBPS
			value.downloadBPS += device.DownloadBPS
			value.seen = true
			remote[device.ID] = value
		}
	}
	day := now.In(shanghai).Format("2006-01-02")
	for _, l := range db.Licenses {
		row := OpsLicense{ID: l.ID, Disabled: l.Disabled, Created: l.Created, Note: o.db.Licenses[l.ID], Devices: []OpsDevice{}}
		for _, d := range db.Devices {
			if d.LicenseID != l.ID {
				continue
			}
			if !d.Revoked {
				row.DeviceCount++
			}
			key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(d.PublicKey))
			fingerprint := ""
			if key != nil {
				fingerprint = ssh.FingerprintSHA256(key)
			}
			v, live := o.deviceLocked(d.ID)
			remoteLive := remote[d.ID]
			lastSeen := v.LastSeen
			if remoteLive.lastSeen > lastSeen {
				lastSeen = remoteLive.lastSeen
			}
			uploadBPS, downloadBPS := live.UploadBPS, live.DownloadBPS
			if remoteLive.seen {
				upload, download := float64(remoteLive.uploadBPS), float64(remoteLive.downloadBPS)
				if uploadBPS != nil {
					upload += *uploadBPS
				}
				if downloadBPS != nil {
					download += *downloadBPS
				}
				uploadBPS, downloadBPS = &upload, &download
			}
			today := v.Days[day]
			row.Devices = append(row.Devices, OpsDevice{ID: d.ID, Revoked: d.Revoked, Created: d.Created, Fingerprint: fingerprint, Note: v.Note, LastSeen: lastSeen, Active: live.Active + remoteLive.active, OnlineSessions: live.Online + remoteLive.online, Traffic: v.Traffic, TodayUpload: today.Upload, TodayDownload: today.Download, UploadBPS: uploadBPS, DownloadBPS: downloadBPS})
		}
		out.Licenses = append(out.Licenses, row)
	}
	return out
}

type ServerStats struct {
	Uptime        *float64 `json:"uptime_seconds"`
	ServiceUptime float64  `json:"service_uptime_seconds"`
	CPU           *float64 `json:"cpu_percent"`
	MemoryTotal   *uint64  `json:"memory_total_bytes"`
	MemoryUsed    *uint64  `json:"memory_used_bytes"`
	DiskTotal     *uint64  `json:"disk_total_bytes"`
	DiskFree      *uint64  `json:"disk_free_bytes"`
	NetworkRX     *uint64  `json:"network_rx_bytes"`
	NetworkTX     *uint64  `json:"network_tx_bytes"`
}
