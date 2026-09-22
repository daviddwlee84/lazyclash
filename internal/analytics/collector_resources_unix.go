//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package analytics

import (
	"golang.org/x/sys/unix"
	"runtime"
)

func collectorResources() (cpuSeconds float64, peakRSSBytes int64) {
	var r unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &r) != nil {
		return
	}
	cpuSeconds = float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
	peakRSSBytes = int64(r.Maxrss)
	if runtime.GOOS != "darwin" {
		peakRSSBytes *= 1024
	}
	return
}
