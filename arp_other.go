//go:build !darwin && !linux && !windows

package main

import (
	"fmt"
	"runtime"
	"time"
)

// maybeHandleARPTableFlag is a no-op here - see arp_darwin.go, the only
// platform with a privilege-elevation flag to handle.
func maybeHandleARPTableFlag() {}

// readHostARPTable has no implementation outside darwin/linux/windows -
// see arp_darwin.go, arp_linux.go, and arp_windows.go for the three real
// ones.
func readHostARPTable(notify func(string)) (map[string]string, error) {
	return nil, fmt.Errorf(`"refresh mac-address-table" has no ARP-table implementation for %s`, runtime.GOOS)
}

// checkReachability falls back to the TCP-based probe here too, same as
// arp_linux.go, for symmetry - in practice this platform's
// readHostARPTable above always errors first, so this never actually
// runs.
func checkReachability(ips []string, notify func(string)) (map[string]bool, error) {
	result := map[string]bool{}
	for _, ip := range ips {
		result[ip] = tcpProbeReachable(ip, 400*time.Millisecond)
	}
	return result, nil
}
