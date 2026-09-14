package main

import (
	"testing"
	"time"
)

func healthyNode(id string, load float64, now time.Time) NodeStatus {
	return NodeStatus{ID: id, Label: id, Healthy: true, UpdatedAt: now, Utilization: load}
}

func TestNodeSelectorAutoOffloadsTokyoAtHighWatermark(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewNodeSelector(5*time.Minute, 15*time.Second)
	s.Update(healthyNode("tokyo", 0.71, now))
	s.Update(healthyNode("osaka", 0.20, now))

	got, err := s.Select("device-a", PreferenceAuto, nil, now)
	if err != nil || got.ID != "osaka" {
		t.Fatalf("got node=%q err=%v, want osaka", got.ID, err)
	}
}
func TestNodeSelectorUsesHysteresisAndStickiness(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewNodeSelector(5*time.Minute, 15*time.Second)
	s.Update(healthyNode("tokyo", 0.71, now))
	s.Update(healthyNode("osaka", 0.20, now))
	first, err := s.Select("device-a", PreferenceAuto, nil, now)
	if err != nil || first.ID != "osaka" {
		t.Fatalf("first assignment = %q, %v", first.ID, err)
	}

	// A new device returns to Tokyo only after the low watermark has held for
	// two minutes. The existing device stays on Osaka for the assignment TTL.
	s.Update(healthyNode("tokyo", 0.54, now.Add(time.Minute)))
	s.Update(healthyNode("osaka", 0.20, now.Add(time.Minute)))
	if got, _ := s.Select("device-b", PreferenceAuto, nil, now.Add(time.Minute)); got.ID != "osaka" {
		t.Fatalf("hysteresis released too soon: %q", got.ID)
	}
	s.Update(healthyNode("tokyo", 0.54, now.Add(3*time.Minute+time.Second)))
	s.Update(healthyNode("osaka", 0.20, now.Add(3*time.Minute+time.Second)))
	if got, _ := s.Select("device-b", PreferenceAuto, nil, now.Add(3*time.Minute+time.Second)); got.ID != "osaka" {
		t.Fatalf("sticky assignment changed: %q", got.ID)
	}
	if got, _ := s.Select("device-c", PreferenceAuto, nil, now.Add(3*time.Minute+time.Second)); got.ID != "tokyo" {
		t.Fatalf("low-watermark recovery did not restore Tokyo: %q", got.ID)
	}
}

func TestNodeSelectorHonorsPreferenceAndFallsBack(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewNodeSelector(5*time.Minute, 15*time.Second)
	s.Update(healthyNode("tokyo", 0.20, now))
	osaka := healthyNode("osaka", 0.20, now)
	s.Update(osaka)

	if got, _ := s.Select("device-a", PreferenceOsaka, nil, now); got.ID != "osaka" {
		t.Fatalf("manual Osaka preference returned %q", got.ID)
	}
	osaka.Draining = true
	s.Update(osaka)
	if got, _ := s.Select("device-b", PreferenceOsaka, nil, now); got.ID != "tokyo" {
		t.Fatalf("draining Osaka did not fall back: %q", got.ID)
	}
}

func TestNodeSelectorRejectsPoorClientPathForAuto(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewNodeSelector(5*time.Minute, 15*time.Second)
	s.Update(healthyNode("tokyo", 0.72, now))
	s.Update(healthyNode("osaka", 0.10, now))
	quality := map[string]NodeQuality{"osaka": {P95: 801 * time.Millisecond}}

	if got, _ := s.Select("device-a", PreferenceAuto, quality, now); got.ID != "tokyo" {
		t.Fatalf("poor Osaka path selected: %q", got.ID)
	}
}

func TestNodeSelectorRejectsStaleNodes(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewNodeSelector(5*time.Minute, 15*time.Second)
	s.Update(healthyNode("tokyo", 0.20, now.Add(-16*time.Second)))
	s.Update(healthyNode("osaka", 0.20, now))

	if got, _ := s.Select("device-a", PreferenceTokyo, nil, now); got.ID != "osaka" {
		t.Fatalf("stale Tokyo did not fall back: %q", got.ID)
	}
}

func TestNodeSelectorBoundsStickyAssignments(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewNodeSelector(5*time.Minute, 15*time.Second)
	s.Update(healthyNode("tokyo", 0.20, now))
	s.Update(healthyNode("osaka", 0.20, now))

	for i := 0; i < 10_100; i++ {
		if _, err := s.Select(string(rune(i))+"-device", PreferenceAuto, nil, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.assignments) > 10_000 {
		t.Fatalf("sticky assignment table grew to %d entries", len(s.assignments))
	}
}

func TestNodeSelectorUsesTokyoCN2BeforeOsakaWhenTokyoOffloads(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewNodeSelector(5*time.Minute, 15*time.Second)
	s.Update(healthyNode("tokyo", 0.75, now))
	s.Update(healthyNode("tokyo_cn2", 0.20, now))
	s.Update(healthyNode("osaka", 0.10, now))

	if got, err := s.Select("device-cn2", PreferenceAuto, nil, now); err != nil || got.ID != "tokyo_cn2" {
		t.Fatalf("got node=%q err=%v, want tokyo_cn2", got.ID, err)
	}
}

func TestNodeSelectorHonorsTokyoCN2PreferenceAndFallsBackToTokyo(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewNodeSelector(5*time.Minute, 15*time.Second)
	s.Update(healthyNode("tokyo", 0.20, now))
	cn2 := healthyNode("tokyo_cn2", 0.20, now)
	s.Update(cn2)
	s.Update(healthyNode("osaka", 0.20, now))

	if got, _ := s.Select("device-a", PreferenceTokyoCN2, nil, now); got.ID != "tokyo_cn2" {
		t.Fatalf("manual Tokyo CN2 preference returned %q", got.ID)
	}
	cn2.Draining = true
	s.Update(cn2)
	if got, _ := s.Select("device-b", PreferenceTokyoCN2, nil, now); got.ID != "tokyo" {
		t.Fatalf("draining Tokyo CN2 did not fall back to Tokyo: %q", got.ID)
	}
}

func TestNodeSelectorLegacySelectionNeverReturnsTokyoCN2(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewNodeSelector(5*time.Minute, 15*time.Second)
	s.Update(healthyNode("tokyo", 0.75, now))
	s.Update(healthyNode("tokyo_cn2", 0.05, now))
	s.Update(healthyNode("osaka", 0.20, now))

	got, err := s.SelectLegacy("legacy-device", PreferenceAuto, nil, now)
	if err != nil || got.ID != "osaka" {
		t.Fatalf("legacy selection got node=%q err=%v, want osaka", got.ID, err)
	}
}
