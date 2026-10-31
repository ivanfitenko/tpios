//go:build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/route"
)

// arpTableFlag and arpProbeFlag are hidden flags this same binary
// re-invokes itself with (see readARPViaElevatedSelf/checkReachability
// below) to do one privileged thing and exit - never meant to be typed
// by a human.
const (
	arpTableFlag = "-print-arp-table"
	arpProbeFlag = "-arp-probe"
)

// maybeHandleARPTableFlag is called first thing in main(), before any
// normal flag parsing - if this process was re-invoked with one of the
// flags above (which only readARPViaElevatedSelf/checkReachability ever
// do, always as a privilege-elevated child), it does that one thing and
// exits immediately, never reaching the normal switch-connecting code
// path. On every other platform this is a no-op - see arp_linux.go/
// arp_other.go.
func maybeHandleARPTableFlag() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case arpTableFlag:
		if len(os.Args) != 2 {
			return
		}
		table, err := readARPViaSysctl()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for ip, mac := range table {
			fmt.Println(ip, mac)
		}
		os.Exit(0)
	case arpProbeFlag:
		for _, ip := range os.Args[2:] {
			fmt.Println(ip, arpProbeOne(ip))
		}
		os.Exit(0)
	}
}

// readHostARPTable reads this Mac's ARP table. If already root (i.e. this
// is the elevated child spawned by readARPViaElevatedSelf, or the user
// just ran tpios under sudo directly), it reads the kernel table in-
// process; otherwise it transparently re-invokes itself through a native
// macOS privilege prompt for just that one read - notify is called right
// before that prompt might appear, so the user sees a line from tpios
// itself explaining where the sudo/Touch ID prompt is about to come from,
// rather than an unexplained system dialog popping up out of nowhere.
func readHostARPTable(notify func(string)) (map[string]string, error) {
	if os.Geteuid() == 0 {
		return readARPViaSysctl()
	}
	return readARPViaElevatedSelf(notify)
}

// readARPViaSysctl reads the ARP table directly via the BSD routing socket
// sysctl (NET_RT_FLAGS + RTF_LLINFO) - the same kernel data arp(8) itself
// reads, just in-process instead of shelling out to it. Requires root:
// confirmed empirically that run unprivileged, the sysctl call succeeds
// (no error at all, not even EPERM) but returns zero bytes - which is why
// readHostARPTable checks os.Geteuid() itself rather than trying this
// first and inferring privilege from an empty result.
//
// Addrs within a RouteMessage are indexed by RTAX_* constants, not just
// "whichever address types happen to be present" - RTAX_DST holds the
// resolved host's IP, RTAX_GATEWAY holds its link-layer (MAC) address.
// Scanning Addrs with a type switch instead of these fixed indices looks
// like it should work but silently misattributes IPs to the wrong MACs
// (verified live - it reliably picked up a stray Inet4Addr field, likely
// a netmask slot, and paired every single MAC with the same wrong IP).
func readARPViaSysctl() (map[string]string, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBType(syscall.NET_RT_FLAGS), syscall.RTF_LLINFO)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBType(syscall.NET_RT_FLAGS), rib)
	if err != nil {
		return nil, err
	}
	table := map[string]string{}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok1 := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		gw, ok2 := rm.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok1 || !ok2 || len(gw.Addr) != 6 {
			continue
		}
		mac := gw.Addr
		table[net.IP(dst.IP[:]).String()] = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}
	return table, nil
}

// readARPViaElevatedSelf re-invokes this same tpios binary with the hidden
// arpTableFlag under "sudo" - deliberately plain sudo, not AppleScript's
// "do shell script ... with administrator privileges". The latter was
// tried first and works, but its dialog (SecurityAgent, the older
// Authorization Services UI) only ever accepts a password, never Touch
// ID - biometric authorization prompts need a different, newer API that
// requires a signed, entitled app bundle, which an ad-hoc-built Go binary
// isn't. Plain "sudo" goes through the standard PAM stack instead, which
// on Touch ID hardware commonly has pam_tid.so wired in (default on many
// Apple Silicon Macs since recent macOS versions) - the exact same
// mechanism that already lets "sudo" in Terminal prompt for a fingerprint.
// Users are also simply more likely to trust a familiar terminal "sudo"
// prompt than an unfamiliar GUI dialog popped up by an unsigned tool.
//
// Stdin/Stderr are inherited from the real controlling terminal so sudo's
// own prompt (fingerprint or password) displays and reads normally,
// exactly as if the user had typed "sudo" themselves; only Stdout is
// captured, carrying nothing but the elevated child's "ip mac" lines (see
// maybeHandleARPTableFlag) - sudo itself writes its prompts to the
// terminal device directly, not to stdout, so the two never mix.
//
// Only that one re-invocation runs as root, just long enough to print the
// ARP table; the tpios process the user is actually interacting with
// (this one) never becomes root itself. sudo caches a recent
// authentication for a few minutes on its own, so calling this twice in
// quick succession (refreshMacAddressTable does, to fail fast before
// sweeping and again for real data after) typically only prompts once.
func readARPViaElevatedSelf(notify func(string)) (map[string]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if notify != nil {
		notify("Requesting elevated privileges (sudo) to read the host's ARP table - you may see an authentication prompt.")
	}
	cmd := exec.Command("sudo", exe, arpTableFlag)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf(`reading the ARP table needs root on macOS - sudo authentication failed or was cancelled: %w`, err)
	}
	fields := strings.Fields(string(out))
	table := map[string]string{}
	for i := 0; i+1 < len(fields); i += 2 {
		table[fields[i]] = fields[i+1]
	}
	return table, nil
}

// arpProbeOne is the Layer-2 equivalent of "arping ip": delete whatever
// ARP cache entry already exists for ip (forcing the kernel to issue a
// brand new ARP "who-has" the next time anything addresses it, rather
// than reusing a stale cached MAC), trigger that resolution with a quick
// outbound connection attempt, wait briefly, then check whether it
// actually resolved. Unlike a TCP-based reachability check, this doesn't
// depend on ip's own application layer (or host firewall) responding to
// anything - ARP is a prerequisite for any IP communication at all, so
// no sane host firewall filters it, and a switch port that's actually
// down can't deliver the ARP broadcast either way (confirmed live: an
// admin-down port blocks everything at the link layer, not just TCP).
// Requires root for "arp -d" - only ever called from within the already-
// elevated child process spawned by checkReachability, never directly.
func arpProbeOne(ip string) bool {
	exec.Command("arp", "-d", ip).Run() // best-effort; fine if already gone
	pokeARP(ip)
	time.Sleep(300 * time.Millisecond)
	table, err := readARPViaSysctl()
	if err != nil {
		return false
	}
	_, resolved := table[ip]
	return resolved
}

// checkReachability runs arpProbeOne for every ip, batched into one
// elevated re-invocation (one sudo prompt/process spawn for the whole
// batch, not one per IP) when not already root.
func checkReachability(ips []string, notify func(string)) (map[string]bool, error) {
	if os.Geteuid() == 0 {
		result := map[string]bool{}
		for _, ip := range ips {
			result[ip] = arpProbeOne(ip)
		}
		return result, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if notify != nil {
		notify("Requesting elevated privileges (sudo) to test port reachability - you may see an authentication prompt.")
	}
	args := append([]string{exe, arpProbeFlag}, ips...)
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf(`testing reachability needs root on macOS - sudo authentication failed or was cancelled: %w`, err)
	}
	fields := strings.Fields(string(out))
	result := map[string]bool{}
	for i := 0; i+1 < len(fields); i += 2 {
		result[fields[i]] = fields[i+1] == "true"
	}
	return result, nil
}
