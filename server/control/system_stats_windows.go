//go:build !linux

package main

type systemSampler struct{}

func (s *systemSampler) Sample(_ string, uptime float64) ServerStats {
	return ServerStats{ServiceUptime: uptime}
}
