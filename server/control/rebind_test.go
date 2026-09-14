package main

import "testing"

func TestDisabledCodeAllowsNewCodeForSameDevice(t *testing.T) {
	s, _, oldID, oldCode := fixture(t)
	pub, _ := testKey()
	d, _, e := s.access(oldCode, pub, true)
	if e != nil {
		t.Fatal(e)
	}
	newID, newCode, e := s.Create()
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.access(newCode, pub, true); e == nil {
		t.Fatal("active binding moved")
	}
	if e = s.Disable(oldID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.access("", pub, false); e == nil {
		t.Fatal("disabled code still authorizes")
	}
	moved, count, e := s.access(newCode, pub, true)
	if e != nil {
		t.Fatalf("disabled old code blocked new activation: %v", e)
	}
	if moved.ID != d.ID || moved.LicenseID != newID || count != 1 {
		t.Fatal("incorrect binding or slot count")
	}
	if _, count, e = s.access(newCode, pub, true); e != nil || count != 1 {
		t.Fatal("repeat activation consumed slot")
	}
	if _, _, e = s.access(oldCode, pub, true); e == nil {
		t.Fatal("old disabled code resurrected")
	}
	reopened, e := OpenStore(s.dir)
	if e != nil {
		t.Fatal(e)
	}
	moved, _, e = reopened.access("", pub, false)
	if e != nil || moved.LicenseID != newID {
		t.Fatal("migration not persisted")
	}
}
func TestRebindingRespectsCapacityAndExplicitDeviceRevocation(t *testing.T) {
	s, _, oldID, oldCode := fixture(t)
	pub, _ := testKey()
	d, _, e := s.access(oldCode, pub, true)
	if e != nil {
		t.Fatal(e)
	}
	_, newCode, e := s.Create()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		p, _ := testKey()
		if _, _, e = s.access(newCode, p, true); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.Disable(oldID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.access(newCode, pub, true); e == nil || e.Error() != "device_limit" {
		t.Fatalf("expected device_limit: %v", e)
	}
	if s.db.Devices[0].LicenseID != oldID {
		t.Fatal("failed migration changed binding")
	}
	_, emptyCode, e := s.Create()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Revoke(d.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.access(emptyCode, pub, true); e == nil {
		t.Fatal("explicit device ban bypassed")
	}
}
