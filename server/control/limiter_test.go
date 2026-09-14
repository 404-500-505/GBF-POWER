package main

import (
	"testing"
	"time"
)

func TestSustainedLimiterAllowsShortBurstThenCaps(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 100)
	if l.Observe("device-a", UploadDirection, 20_000_000, now) {
		t.Fatal("short burst was capped")
	}
	if !l.Observe("device-a", UploadDirection, 20_000_000, now.Add(31*time.Second)) {
		t.Fatal("sustained high upload was not capped")
	}
}
func TestSustainedLimiterTracksDirectionsAndDevicesSeparately(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 100)
	l.Observe("device-a", UploadDirection, 20_000_000, now)
	if !l.Observe("device-a", UploadDirection, 20_000_000, now.Add(31*time.Second)) {
		t.Fatal("device-a upload should be capped")
	}
	if l.Observe("device-a", DownloadDirection, 20_000_000, now.Add(31*time.Second)) {
		t.Fatal("device-a download inherited upload state")
	}
	if l.Observe("device-b", UploadDirection, 20_000_000, now.Add(31*time.Second)) {
		t.Fatal("device-b inherited device-a state")
	}
}

func TestSustainedLimiterRecoversAfterLowTraffic(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 100)
	l.Observe("device-a", UploadDirection, 20_000_000, now)
	l.Observe("device-a", UploadDirection, 20_000_000, now.Add(31*time.Second))
	if !l.Observe("device-a", UploadDirection, 4_000_000, now.Add(40*time.Second)) {
		t.Fatal("cap cleared before recovery window")
	}
	if l.Observe("device-a", UploadDirection, 4_000_000, now.Add(101*time.Second)) {
		t.Fatal("cap did not clear after sustained low traffic")
	}
}

func TestSustainedLimiterBoundsTrackedDevices(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 1)
	l.Observe("device-a", UploadDirection, 1, now)
	l.Observe("device-b", UploadDirection, 1, now)
	if got := l.Tracked(); got != 1 {
		t.Fatalf("tracked %d devices, want 1", got)
	}
}

func TestSustainedLimiterExposesCurrentDirectionState(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 10)
	l.Observe("device-a", DownloadDirection, 20_000_000, now)
	l.Observe("device-a", DownloadDirection, 20_000_000, now.Add(31*time.Second))
	if !l.Limited("device-a", DownloadDirection) || l.Limited("device-a", UploadDirection) {
		t.Fatal("directional limit state is incorrect")
	}
}
