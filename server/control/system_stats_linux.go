package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

type systemSampler struct {
	total, idle uint64
	hasCPU      bool
}

func (s *systemSampler) Sample(dir string, uptime float64) ServerStats {
	out := ServerStats{ServiceUptime: uptime}
	if b, e := os.ReadFile("/proc/uptime"); e == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			if v, e := strconv.ParseFloat(f[0], 64); e == nil {
				out.Uptime = &v
			}
		}
	}
	if b, e := os.ReadFile("/proc/stat"); e == nil {
		line := strings.SplitN(string(b), "\n", 2)[0]
		f := strings.Fields(line)
		if len(f) >= 9 && f[0] == "cpu" {
			var total, idle uint64
			valid := true
			for i, v := range f[1:9] {
				n, e := strconv.ParseUint(v, 10, 64)
				if e != nil {
					valid = false
					break
				}
				total += n
				if i == 3 || i == 4 {
					idle += n
				}
			}
			if valid {
				if s.hasCPU && total > s.total && idle >= s.idle && idle-s.idle <= total-s.total {
					v := 100 * (1 - float64(idle-s.idle)/float64(total-s.total))
					out.CPU = &v
				}
				s.total = total
				s.idle = idle
				s.hasCPU = true
			}
		}
	}
	if b, e := os.ReadFile("/proc/meminfo"); e == nil {
		values := map[string]uint64{}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if v, e := strconv.ParseUint(f[1], 10, 64); e == nil {
					values[f[0]] = v * 1024
				}
			}
		}
		total, ok := values["MemTotal:"]
		available, aok := values["MemAvailable:"]
		if ok {
			out.MemoryTotal = &total
		}
		if ok && aok && total >= available {
			used := total - available
			out.MemoryUsed = &used
		}
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(dir, &fs) == nil {
		total := fs.Blocks * uint64(fs.Bsize)
		free := fs.Bavail * uint64(fs.Bsize)
		out.DiskTotal = &total
		out.DiskFree = &free
	}
	if b, e := os.ReadFile("/proc/net/dev"); e == nil {
		var rx, tx uint64
		valid := true
		found := false
		for _, line := range strings.Split(string(b), "\n") {
			name, body, ok := strings.Cut(line, ":")
			if !ok || strings.TrimSpace(name) == "lo" {
				continue
			}
			f := strings.Fields(body)
			if len(f) < 16 {
				valid = false
				break
			}
			r, re := strconv.ParseUint(f[0], 10, 64)
			t, te := strconv.ParseUint(f[8], 10, 64)
			if re != nil || te != nil {
				valid = false
				break
			}
			rx += r
			tx += t
			found = true
		}
		if valid && found {
			out.NetworkRX = &rx
			out.NetworkTX = &tx
		}
	}
	return out
}
