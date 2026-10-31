//go:build windows

package main

import (
	"os/exec"
	"strings"
	"time"
)

// maybeHandleARPTableFlag is a no-op on Windows - no privilege-elevation
// flag to handle; "arp -a" reads the cache without elevation, so there's
// nothing to re-invoke as an elevated child for.
func maybeHandleARPTableFlag() {}

// readHostARPTable shells out to Windows's own "arp -a", which (unlike
// the BSD/Darwin equivalent in arp_darwin.go) needs no elevation at all
// to read - only "arp -d" (deletion, used for the ARP-probe reachability
// technique on Darwin) needs Administrator, which is why checkReachability
// below falls back to the TCP-based probe instead of attempting that here.
// Output looks like:
//
//	Interface: 192.168.1.50 --- 0xa
//	  Internet Address      Physical Address      Type
//	  192.168.1.1           00-1a-2b-3c-4d-5e      dynamic
//
// Possibly repeated once per network adapter - all sections are parsed.
// MAC addresses use dashes, not colons - converted before normalizeMAC.
// Unverified on a real Windows machine - this matches Windows's
// documented arp -a format, but nobody working on this project has
// actually run it there.
func readHostARPTable(notify func(string)) (map[string]string, error) {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, err
	}
	table := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || !strings.Contains(fields[0], ".") || !strings.Contains(fields[1], "-") {
			continue // "Interface: ..." lines, the column header, and blank lines all fail this
		}
		table[fields[0]] = normalizeMAC(strings.ReplaceAll(fields[1], "-", ":"))
	}
	return table, nil
}

// checkReachability has no privileged ARP-probe path on Windows - "arp -d"
// needs Administrator (UAC elevation), a genuinely different mechanism
// from macOS's sudo and not implemented here - falls back to the TCP-based
// probe (tcpProbeReachable, main.go), same as Linux/other. Less reliable
// against a host with a locked-down firewall (see concerns.md), but needs
// no elevation at all.
func checkReachability(ips []string, notify func(string)) (map[string]bool, error) {
	result := map[string]bool{}
	for _, ip := range ips {
		result[ip] = tcpProbeReachable(ip, 400*time.Millisecond)
	}
	return result, nil
}
