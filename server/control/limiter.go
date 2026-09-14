package main

import (
	"sync"
	"time"
)

type TrafficDirection uint8

const (
	UploadDirection TrafficDirection = iota
	DownloadDirection
)

type limiterDirectionState struct {
	highSince time.Time
	lowSince  time.Time
	limited   bool
}

type limiterDeviceState struct {
	directions [2]limiterDirectionState
}

type SustainedLimiter struct {
	mu         sync.Mutex
	highBPS    uint64
	lowBPS     uint64
	highFor    time.Duration
	lowFor     time.Duration
	maxDevices int
	devices    map[string]*limiterDeviceState
}

func NewSustainedLimiter(highBPS, lowBPS uint64, highFor, lowFor time.Duration, maxDevices int) *SustainedLimiter {
	return &SustainedLimiter{highBPS: highBPS, lowBPS: lowBPS, highFor: highFor, lowFor: lowFor, maxDevices: maxDevices, devices: make(map[string]*limiterDeviceState)}
}

func (l *SustainedLimiter) Observe(deviceID string, direction TrafficDirection, bps uint64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if direction > DownloadDirection {
		return false
	}
	device := l.devices[deviceID]
	if device == nil {
		if len(l.devices) >= l.maxDevices {
			return false
		}
		device = &limiterDeviceState{}
		l.devices[deviceID] = device
	}
	state := &device.directions[direction]
	if state.limited {
		if bps < l.lowBPS {
			if state.lowSince.IsZero() {
				state.lowSince = now
			} else if now.Sub(state.lowSince) >= l.lowFor {
				state.limited = false
				state.highSince = time.Time{}
				state.lowSince = time.Time{}
			}
		} else {
			state.lowSince = time.Time{}
		}
		return state.limited
	}
	if bps > l.highBPS {
		if state.highSince.IsZero() {
			state.highSince = now
		} else if now.Sub(state.highSince) >= l.highFor {
			state.limited = true
			state.lowSince = time.Time{}
		}
	} else {
		state.highSince = time.Time{}
	}
	return state.limited
}

func (l *SustainedLimiter) Tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.devices)
}

func (l *SustainedLimiter) LimitBPS() uint64 { return l.highBPS }

func (l *SustainedLimiter) Limited(deviceID string, direction TrafficDirection) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	device := l.devices[deviceID]
	return device != nil && direction <= DownloadDirection && device.directions[direction].limited
}
