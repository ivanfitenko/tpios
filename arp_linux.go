//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// maybeHandleARPTableFlag is a no-op on Linux - the privilege-elevation
// dance in arp_darwin.go exists only because macOS's ARP table needs root;
// /proc/net/arp below needs no such thing, so there's no flag to handle.
func maybeHandleARPTableFlag() {}

// readHostARPTable reads /proc/net/arp - world-readable on Linux, unlike
// the BSD/Darwin equivalent (see arp_darwin.go), so no root is needed here
// in practice. Format is a header line followed by one line per entry:
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
//
// An all-zero HW address means an incomplete/unresolved entry - skipped,
// matching how arp_darwin.go skips entries with no resolved link address.
func readHostARPTable(notify func(string)) (map[string]string, error) {
	f, err := os.Open("/proc/net/arp")
	if errors.Is(err, os.ErrPermission) {
		// Not expected on a normal Linux install - /proc/net/arp is world-
		// readable there - but some locked-down/restricted setups (certain
		// containers, hardened kernels) could plausibly deny this. Unlike
		// macOS there's no native in-app escalation prompt to fall back to
		// here (pkexec/polkit exists but isn't something to depend on for
		// this), so just say what to do rather than attempting magic.
		return nil, fmt.Errorf(`reading %s needs root on this system - re-run tpios as root for "refresh mac-address-table", then back to your normal user for everything else: %w`, "/proc/net/arp", err)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	table := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Scan() // header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		ip, mac := fields[0], fields[3]
		if mac == "00:00:00:00:00:00" {
			continue
		}
		table[ip] = normalizeMAC(mac)
	}
	return table, sc.Err()
}

// checkReachability has no privileged ARP-probe path on Linux (deleting
// an ARP entry needs root/CAP_NET_ADMIN, same as macOS, but per explicit
// instruction PolicyKit/pkexec isn't something to depend on here) - falls
// back to the TCP-based probe (tcpProbeReachable, main.go), which is
// usable without any elevation but less reliable against a host with a
// locked-down firewall - see concerns.md.
func checkReachability(ips []string, notify func(string)) (map[string]bool, error) {
	result := map[string]bool{}
	for _, ip := range ips {
		result[ip] = tcpProbeReachable(ip, 400*time.Millisecond)
	}
	return result, nil
}
