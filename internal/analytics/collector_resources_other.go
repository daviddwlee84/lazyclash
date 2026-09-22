//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly

package analytics

func collectorResources() (float64, int64) { return 0, 0 }
