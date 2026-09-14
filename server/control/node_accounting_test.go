package main

import (
	"testing"
	"time"
)

func TestNodeAccountingDetectsSustainedRateAndReportsWithoutBanning(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	a := NewNodeAccounting("osaka", 1_000_000_000, NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 100))
	a.Sample(now)
	for second := 5; second <= 35; second += 5 {
		a.Add("aaaaaaaaaaaaaaaaaaaaaaaa", true, 12_500_000)
		a.Sample(now.Add(time.Duration(second) * time.Second))
	}
	status := a.Status(now.Add(35 * time.Second))
	if status.UploadBPS != 20_000_000 || status.Throttled != 0 || status.Connections != 0 {
		t.Fatalf("unexpected Osaka status: %+v", status)
	}
	if !a.Limited("aaaaaaaaaaaaaaaaaaaaaaaa", true) {
		t.Fatal("sustained upload was not marked for shaping")
	}
}
func TestNodeAccountingCountsOnlyActiveThrottledDevices(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	a := NewNodeAccounting("osaka", 1_000_000_000, NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 100))
	a.Connection("active-device", 1)
	a.Sample(now)
	for second := 5; second <= 35; second += 5 {
		a.Add("active-device", true, 12_500_000)
		a.Sample(now.Add(time.Duration(second) * time.Second))
	}
	status := a.Status(now.Add(35 * time.Second))
	if status.Devices != 1 || status.Throttled != 1 {
		t.Fatalf("active throttled device missing from status: %+v", status)
	}
}

func TestNodeAccountingTracksActiveDevicesAndConnections(t *testing.T) {
	a := NewNodeAccounting("osaka", 1_000_000_000, NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 100))
	a.Connection("a", 1)
	a.Connection("a", 1)
	a.Connection("b", 1)
	status := a.Status(time.Now())
	if status.Devices != 2 || status.Connections != 3 {
		t.Fatalf("unexpected counts: %+v", status)
	}
	a.Connection("a", -2)
	a.Connection("b", -1)
	status = a.Status(time.Now())
	if status.Devices != 0 || status.Connections != 0 {
		t.Fatalf("connections did not clear: %+v", status)
	}
}

func TestNodeAccountingTracksAuthenticatedSessionsWithoutForwarding(t *testing.T) {
	a := NewNodeAccounting("osaka", 1_000_000_000, NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 100))
	a.Session("aaaaaaaaaaaaaaaaaaaaaaaa", 1)
	status := a.Status(time.Now())
	if status.Devices != 1 || status.Connections != 0 || len(status.DeviceStates) != 1 || status.DeviceStates[0].OnlineSessions != 1 {
		t.Fatalf("authenticated session missing from status: %+v", status)
	}
	a.Session("aaaaaaaaaaaaaaaaaaaaaaaa", -1)
	status = a.Status(time.Now())
	if status.Devices != 0 || status.Connections != 0 {
		t.Fatalf("authenticated session did not clear: %+v", status)
	}
}
