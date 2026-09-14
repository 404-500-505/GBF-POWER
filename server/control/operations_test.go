package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOperationsSnapshotAndNotes(t *testing.T) {
	s, _, lid, code := fixture(t)
	pub, _ := testKey()
	dev, _, err := s.access(code, pub, true)
	if err != nil {
		t.Fatal(err)
	}
	h := NewAdmin(s)
	w := request(h, "/snapshot", map[string]string{})
	requireStatus(t, w, 200, "")
	var snap map[string]any
	if json.Unmarshal(w.Body.Bytes(), &snap) != nil {
		t.Fatal("invalid snapshot")
	}
	for _, k := range []string{"sampled_at", "server", "licenses", "metering", "events"} {
		if _, ok := snap[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
	for _, item := range []struct{ path, id, note string }{{"/note-license", lid, "运营客户 🌸"}, {"/note-device", dev.ID, "设备一"}} {
		requireStatus(t, request(h, item.path, map[string]string{"id": item.id, "note": item.note}), 200, "")
	}
	requireStatus(t, request(h, "/note-device", map[string]string{"id": dev.ID, "note": strings.Repeat("猫", 501)}), 400, "invalid_request")
	w = request(h, "/snapshot", map[string]string{})
	if strings.Contains(w.Body.String(), code) || strings.Contains(w.Body.String(), codeHash(code)) || strings.Contains(w.Body.String(), pub) {
		t.Fatal("snapshot leaks secrets")
	}
	if !strings.Contains(w.Body.String(), "运营客户 🌸") || !strings.Contains(w.Body.String(), "SHA256:") {
		t.Fatal(w.Body.String())
	}
	old, err := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseDatabase(old); err != nil {
		t.Fatal("state schema changed", err)
	}
	reopened, err := OpenStore(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	w = request(NewAdmin(reopened), "/snapshot", map[string]string{})
	if !strings.Contains(w.Body.String(), "运营客户 🌸") {
		t.Fatal("note lost on reopen", w.Body.String())
	}
}
func TestMeteringConfigurationIsOptionalAndAtomic(t *testing.T) {
	pub, _ := testKey()
	base := map[string]any{"data_dir": t.TempDir(), "listen": "127.0.0.1:18444", "tls_cert": "cert", "tls_key": "key", "node": Node{Host: "node", Port: 2222, Username: "gbfdevice", HostKey: pub}}
	parse := func(m map[string]any) Config {
		b, _ := json.Marshal(m)
		var c Config
		if e := json.Unmarshal(b, &c); e != nil {
			t.Fatal(e)
		}
		return c
	}
	if e := parse(base).Validate(); e != nil {
		t.Fatal("legacy configuration rejected", e)
	}
	base["metering_listen"] = "127.0.0.1:2222"
	if e := parse(base).Validate(); e == nil {
		t.Fatal("incomplete metering configuration accepted")
	}
	base["metering_host_key"] = filepath.Join(t.TempDir(), "host_key")
	base["metering_rules"] = filepath.Join(t.TempDir(), "rules.json")
	if e := parse(base).Validate(); e != nil {
		t.Fatal("complete metering configuration rejected", e)
	}
}

func TestMeteringRatesRetentionAndEventLimit(t *testing.T) {
	s, _, lid, code := fixture(t)
	pub, _ := testKey()
	dev, _, e := s.access(code, pub, true)
	if e != nil {
		t.Fatal(e)
	}
	o := s.ops
	now := time.Now()
	o.Sample(now)
	o.Add(dev.ID, true, 100)
	o.Add(dev.ID, false, 250)
	o.Sample(now.Add(time.Second))
	d := s.Snapshot().Licenses[0].Devices[0]
	if d.UploadBPS == nil || *d.UploadBPS != 100 || d.DownloadBPS == nil || *d.DownloadBPS != 250 {
		t.Fatalf("incorrect sampled rates: %+v", d)
	}
	o.mu.Lock()
	old := now.In(shanghai).AddDate(0, 0, -31).Format("2006-01-02")
	o.db.Devices[dev.ID].Days[old] = Traffic{Upload: 1}
	o.db.Devices[dev.ID].Upload++
	for i := 0; i < 1010; i++ {
		o.eventLocked("note-license", lid)
	}
	o.mu.Unlock()
	if e = o.Flush(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenStore(s.dir)
	if e != nil {
		t.Fatal(e)
	}
	if len(reopened.ops.db.Events) != 1000 {
		t.Fatal("event retention wrong")
	}
	if _, ok := reopened.ops.db.Devices[dev.ID].Days[old]; ok {
		t.Fatal("expired day retained")
	}
	if reopened.ops.db.Devices[dev.ID].Upload != 101 {
		t.Fatal("lifetime total lost")
	}
}

func TestAdminCLIStrictArguments(t *testing.T) {
	for _, args := range [][]string{{"revoke-device", "../bad"}, {"disable-code", "ABC"}, {"note-license", "0123456789abcdef01234567", "%%%"}, {"note-device", "0123456789abcdef01234567", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 501)))}} {
		if err := adminCommand("unused.sock", args); err == nil || strings.Contains(err.Error(), "cannot reach") {
			t.Fatalf("must reject argv before connecting: %v -> %v", args, err)
		}
	}
}

func TestSnapshotDoesNotKeepDeviceOnlineFromStaleRemoteReport(t *testing.T) {
	s, _, _, code := fixture(t)
	pub, _ := testKey()
	device, _, err := s.access(code, pub, true)
	if err != nil {
		t.Fatal(err)
	}
	selector := NewNodeSelector(5*time.Minute, time.Second)
	selector.Update(NodeStatus{
		ID:        "osaka",
		Healthy:   true,
		UpdatedAt: time.Now().Add(-2 * time.Second),
		Devices:   1,
		DeviceStates: []NodeDeviceStatus{{
			ID:             device.ID,
			OnlineSessions: 1,
			LastSeen:       time.Now().Add(-2 * time.Second).Unix(),
		}},
	})
	s.AttachNodeSelector(selector)
	got := s.Snapshot().Licenses[0].Devices[0]
	if got.OnlineSessions != 0 || got.Active != 0 {
		t.Fatalf("stale remote report kept device online: %+v", got)
	}
}
