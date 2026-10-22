// tpios: a Cisco-2960-ish IOS shell for TP-Link EasySmart switches (TL-SG1024DE etc).
// There is no JSON API on these devices - this drives the same *.cgi/*.htm endpoints
// the browser's web UI uses, reverse-engineered by inspecting the real pages.
package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// ------------------------------------------------------------------ Switch --

type Switch struct {
	base      string
	user      string
	pass      string
	portNum   int
	client    *http.Client
	loggedIn  bool
	loginTime time.Time
}

func NewSwitch(ip, user, pass string, portNum int) *Switch {
	jar, _ := cookiejar.New(nil)
	return &Switch{
		base:    "http://" + ip,
		user:    user,
		pass:    pass,
		portNum: portNum,
		// Some writes on this device (e.g. flipping 802.1Q on, device description)
		// apparently commit to flash and can take noticeably longer than a plain
		// page GET - seen exceeding 8s while still succeeding server-side.
		client: &http.Client{Jar: jar, Timeout: 20 * time.Second},
	}
}

// isDialError reports whether err failed before a request ever reached the
// network - a TCP connect() failure, not a response timeout. On macOS a
// brief ARP-cache hiccup on the client can surface as "no route to host"
// for one connection attempt and be gone on the very next one; that's safe
// to retry quickly. A hang *after* connecting (the device itself not
// responding) is a different, more serious failure mode we've seen this
// switch exhibit under load - that must never be retried automatically,
// to avoid piling more connections onto a device that's already struggling.
func isDialError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

func (s *Switch) login() error {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = s.doLogin()
		if lastErr == nil {
			s.loggedIn = true
			s.loginTime = time.Now()
			return nil
		}
		if !isDialError(lastErr) || attempt == maxAttempts {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	return lastErr
}

// loginRejectedError means the switch answered (HTTP-level success) but
// explicitly refused the credentials/session - as opposed to a network or
// device-availability failure. This must never be retried automatically
// (there's no point retrying a wrong password) and must never be treated
// as a successful login.
type loginRejectedError struct{ code int }

func (e *loginRejectedError) Error() string { return "login rejected: " + loginErrTypeMessage(e.code) }

// loginErrTypeMessage decodes this device's logonInfo[0] error code, taken
// from the login page's own JS (window.onload's errType handling).
func loginErrTypeMessage(code int) string {
	switch code {
	case 1:
		return "incorrect username or password"
	case 2:
		return "this user is not allowed to log in"
	case 3, 4:
		return "too many users are already logged in to this switch"
	case 5:
		return "session timed out"
	case 6:
		return "this account still has the factory-default password; tpios doesn't support the forced password-change flow the web UI requires - change the password via the web UI first"
	default:
		return fmt.Sprintf("unrecognized error code %d", code)
	}
}

var logonInfoRe = regexp.MustCompile(`logonInfo\s*=\s*new\s*Array\(\s*([0-9]+)`)

// doLogin posts the credentials and inspects the response body for the
// device's own success/failure signal (logonInfo[0]) - a plain HTTP 200 here
// does NOT mean the login succeeded; the device always answers 200 and just
// re-renders the login page with an error code on bad credentials. Trusting
// the HTTP status alone was the root cause of a bug where a wrong password
// silently "succeeded" and every subsequent page fetch quietly returned the
// login page instead of real data, which parsed as all-empty - rendering
// every port as "down".
func (s *Switch) doLogin() error {
	form := url.Values{"username": {s.user}, "password": {s.pass}, "logon": {"Login"}}
	req, err := http.NewRequest("POST", s.base+"/logon.cgi", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", s.base)
	req.Header.Set("Referer", s.base+"/Logout.htm")
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("switch did not respond to login (device may be slow/overloaded): %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if m := logonInfoRe.FindStringSubmatch(string(body)); m != nil {
		if code, _ := strconv.Atoi(m[1]); code != 0 {
			return &loginRejectedError{code: code}
		}
	}
	return nil
}

func (s *Switch) ensureSession() error {
	if !s.loggedIn || time.Since(s.loginTime) > 540*time.Second {
		return s.login()
	}
	return nil
}

func (s *Switch) rawGet(path string) (string, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		body, err := s.doRawGet(path)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !isDialError(err) || attempt == maxAttempts {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	return "", lastErr
}

func (s *Switch) doRawGet(path string) (string, error) {
	req, err := http.NewRequest("GET", s.base+"/"+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("no response from switch (timeout) - it may be busy, try again shortly: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// get performs a GET, transparently re-logging in once if the session looks stale.
func (s *Switch) get(path string) (string, error) {
	if err := s.ensureSession(); err != nil {
		return "", err
	}
	body, err := s.rawGet(path)
	if err != nil {
		return "", err
	}
	if strings.Contains(body, `name="username"`) {
		if err := s.login(); err != nil {
			return "", err
		}
		body, err = s.rawGet(path)
		if err != nil {
			return "", err
		}
	}
	return body, nil
}

func (s *Switch) logout() {
	_, _ = s.rawGet("Logout.htm")
}

// ------------------------------------------------------------- HTML parsing --

func extractArray(html, name string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(name) + `\s*:\s*\[([^\]]*)\]`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		return ""
	}
	return m[1]
}

func extractScalar(html, name string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(name) + `\s*:\s*([0-9]+)`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		return ""
	}
	return m[1]
}

// extractVar reads a bare `var name = N;` assignment, as opposed to a field
// inside a `{ name: N, ... }` object literal (see extractScalar).
func extractVar(html, name string) string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*=\s*([0-9]+)`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		return ""
	}
	return m[1]
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `'"`)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func splitCSVInts(raw string) []int {
	strs := splitCSV(raw)
	out := make([]int, len(strs))
	for i, v := range strs {
		n, _ := strconv.ParseInt(v, 0, 64) // base 0 handles 0x.. hex masks too
		out[i] = int(n)
	}
	return out
}

// ------------------------------------------------------------ Port settings --

type PortSettings struct {
	State, SpdCfg, SpdAct, FcCfg, FcAct []int // index 0 == port 1
}

func (s *Switch) fetchPortSettings() (*PortSettings, error) {
	html, err := s.get("PortSettingRpm.htm")
	if err != nil {
		return nil, err
	}
	return &PortSettings{
		State:  splitCSVInts(extractArray(html, "state")),
		SpdCfg: splitCSVInts(extractArray(html, "spd_cfg")),
		SpdAct: splitCSVInts(extractArray(html, "spd_act")),
		FcCfg:  splitCSVInts(extractArray(html, "fc_cfg")),
		FcAct:  splitCSVInts(extractArray(html, "fc_act")),
	}, nil
}

func at(a []int, port int) int {
	if port-1 < 0 || port-1 >= len(a) {
		return 0
	}
	return a[port-1]
}

func speedLabel(code int) string {
	switch code {
	case 0:
		return "down"
	case 1:
		return "auto"
	case 2, 3:
		return "10"
	case 4, 5:
		return "100"
	case 6:
		return "1000"
	default:
		return "--"
	}
}

func duplexLabel(code int) string {
	switch code {
	case 2, 4:
		return "half"
	case 3, 5, 6:
		return "full"
	case 1:
		return "auto"
	default:
		return "--"
	}
}

func (s *Switch) setPortState(port, enabled, speed, flow int) error {
	path := fmt.Sprintf("port_setting.cgi?portid=%d&state=%d&speed=%d&flowcontrol=%d&apply=Apply", port, enabled, speed, flow)
	_, err := s.get(path)
	return err
}

// PortStats holds the only real traffic counters this device exposes: good
// and bad packet counts per direction, per port - no byte counts, no error
// taxonomy (CRC/runts/giants/etc), no queue depths. See concerns.md.
type PortStats struct {
	TxGood, TxBad, RxGood, RxBad []int // index 0 == port 1
}

func (s *Switch) fetchPortStats() (*PortStats, error) {
	html, err := s.get("PortStatisticsRpm.htm")
	if err != nil {
		return nil, err
	}
	flat := splitCSVInts(extractArray(html, "pkts")) // [txGood,txBad,rxGood,rxBad] per port, flattened
	n := len(flat) / 4
	st := &PortStats{TxGood: make([]int, n), TxBad: make([]int, n), RxGood: make([]int, n), RxBad: make([]int, n)}
	for i := 0; i < n; i++ {
		st.TxGood[i] = flat[4*i]
		st.TxBad[i] = flat[4*i+1]
		st.RxGood[i] = flat[4*i+2]
		st.RxBad[i] = flat[4*i+3]
	}
	return st, nil
}

// clearPortStats clears counters for every port - the device has one global
// Clear button, no per-port selective clear.
func (s *Switch) clearPortStats() error {
	_, err := s.get("port_statistics_set.cgi?clear=Clear")
	return err
}

// -------------------------------------------------------------------- VLANs --

type Vlan struct {
	ID                 int
	Name               string
	TagMask, UntagMask int
}

type VlanTable struct {
	Enabled bool
	PortNum int
	Vlans   []*Vlan
}

func (vt *VlanTable) byID(id int) *Vlan {
	for _, v := range vt.Vlans {
		if v.ID == id {
			return v
		}
	}
	return nil
}

func (s *Switch) fetchVlans() (*VlanTable, error) {
	html, err := s.get("Vlan8021QRpm.htm")
	if err != nil {
		return nil, err
	}
	vt := &VlanTable{}
	vt.Enabled = extractScalar(html, "state") == "1"
	if n, err := strconv.Atoi(extractScalar(html, "portNum")); err == nil && n > 0 {
		vt.PortNum = n
	} else {
		vt.PortNum = s.portNum
	}
	ids := splitCSVInts(extractArray(html, "vids"))
	names := splitCSV(extractArray(html, "names"))
	tags := splitCSVInts(extractArray(html, "tagMbrs"))
	untags := splitCSVInts(extractArray(html, "untagMbrs"))
	for i, id := range ids {
		v := &Vlan{ID: id}
		if i < len(names) {
			v.Name = names[i]
		}
		if i < len(tags) {
			v.TagMask = tags[i]
		}
		if i < len(untags) {
			v.UntagMask = untags[i]
		}
		vt.Vlans = append(vt.Vlans, v)
	}
	return vt, nil
}

func (s *Switch) writeVlan(vid int, name string, untagMask, tagMask int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "qvlanSet.cgi?vid=%d&vname=%s", vid, url.QueryEscape(name))
	for p := 1; p <= s.portNum; p++ {
		sel := 2 // not member
		if untagMask&(1<<(p-1)) != 0 {
			sel = 0
		} else if tagMask&(1<<(p-1)) != 0 {
			sel = 1
		}
		fmt.Fprintf(&b, "&selType_%d=%d", p, sel)
	}
	b.WriteString("&qvlan_add=" + url.QueryEscape("Add/Modify"))
	_, err := s.get(b.String())
	return err
}

func (s *Switch) ensureQvlanEnabled(vt *VlanTable) error {
	if vt.Enabled {
		return nil
	}
	if _, err := s.get("qvlanSet.cgi?qvlan_en=1&qvlan_mode=Apply"); err != nil {
		return err
	}
	vt.Enabled = true
	return nil
}

func (s *Switch) deleteVlan(vid int) error {
	_, err := s.get(fmt.Sprintf("qvlanSet.cgi?selVlans=%d&qvlan_del=Delete", vid))
	return err
}

func (s *Switch) setPVID(port, vid int) error {
	pbm := 1 << (port - 1)
	_, err := s.get(fmt.Sprintf("vlanPvidSet.cgi?pbm=%d&pvid=%d", pbm, vid))
	return err
}

// fetchPVIDs reads each port's actual configured PVID from the device - this
// is tracked independently of whether 802.1Q filtering is globally enabled,
// and is a real read (unlike inferring PVID from untagged-VLAN membership,
// which is only a proxy and can't be verified as always equivalent).
func (s *Switch) fetchPVIDs() ([]int, error) {
	html, err := s.get("Vlan8021QPvidRpm.htm")
	if err != nil {
		return nil, err
	}
	return splitCSVInts(extractArray(html, "pvids")), nil
}

// portVlanDisplay is what `show interfaces status` / running-config show in
// the "Vlan" column: "trunk" if the port carries any tagged VLAN, else its
// real PVID.
func portVlanDisplay(vt *VlanTable, pvids []int, port int) string {
	bit := 1 << (port - 1)
	for _, v := range vt.Vlans {
		if v.TagMask&bit != 0 {
			return "trunk"
		}
	}
	if port-1 >= 0 && port-1 < len(pvids) && pvids[port-1] > 0 {
		return strconv.Itoa(pvids[port-1])
	}
	return "1"
}

// ------------------------------------------------------------------ SysInfo --

type SysInfo struct {
	Desc, MAC, IP, Mask, Gateway, Firmware, Hardware string
}

func firstCSV(raw string) string {
	items := splitCSV(raw)
	if len(items) == 0 {
		return ""
	}
	return items[0]
}

func (s *Switch) fetchSysInfo() (*SysInfo, error) {
	html, err := s.get("SystemInfoRpm.htm")
	if err != nil {
		return nil, err
	}
	return &SysInfo{
		Desc:     firstCSV(extractArray(html, "descriStr")),
		MAC:      firstCSV(extractArray(html, "macStr")),
		IP:       firstCSV(extractArray(html, "ipStr")),
		Mask:     firstCSV(extractArray(html, "netmaskStr")),
		Gateway:  firstCSV(extractArray(html, "gatewayStr")),
		Firmware: firstCSV(extractArray(html, "firmwareStr")),
		Hardware: firstCSV(extractArray(html, "hardwareStr")),
	}, nil
}

func (s *Switch) setDeviceDescription(name string) error {
	_, err := s.get("system_name_set.cgi?sysName=" + url.QueryEscape(name))
	return err
}

// --------------------------------------------------------- other settings --
// These back the richer `show running-config` below. They're read-only in
// tpios for now (no CLI verb sets them) - see concerns.md for what's been
// verified live vs. best-effort/unverified (LAG in particular).

type IPSetting struct {
	DHCP              bool
	IP, Mask, Gateway string
}

func (s *Switch) fetchIPSetting() (*IPSetting, error) {
	html, err := s.get("IpSettingRpm.htm")
	if err != nil {
		return nil, err
	}
	return &IPSetting{
		DHCP:    extractScalar(html, "state") == "1",
		IP:      firstCSV(extractArray(html, "ipStr")),
		Mask:    firstCSV(extractArray(html, "netmaskStr")),
		Gateway: firstCSV(extractArray(html, "gatewayStr")),
	}, nil
}

func (s *Switch) fetchIgmpSnooping() (bool, error) {
	html, err := s.get("IgmpSnoopingRpm.htm")
	if err != nil {
		return false, err
	}
	return extractScalar(html, "state") == "1", nil
}

func (s *Switch) fetchLoopPrevention() (bool, error) {
	html, err := s.get("LoopPreventionRpm.htm")
	if err != nil {
		return false, err
	}
	return extractVar(html, "lpEn") == "1", nil
}

// setLoopPrevention was verified live with a same-value no-op before being
// trusted for the config-restore feature below.
func (s *Switch) setLoopPrevention(enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.get(fmt.Sprintf("loop_prevention_set.cgi?lpEn=%d", v))
	return err
}

// setIPSetting was verified live end-to-end: changing to a different static
// IP in the same subnet took effect immediately with no reboot (the device
// stopped answering on the old address and started on the new one), and
// switching back to DHCP got the same lease back. Note this means a replay
// that changes the IP/DHCP setting WILL make the current connection stale -
// callers must detect that and stop issuing further requests on this
// Switch rather than let them time out confusingly against a dead address.
func (s *Switch) setIPSetting(dhcp bool, ip, mask, gateway string) error {
	v := "disable"
	if dhcp {
		v = "enable"
	}
	path := fmt.Sprintf("ip_setting.cgi?dhcpSetting=%s&ip_address=%s&ip_netmask=%s&ip_gateway=%s",
		v, url.QueryEscape(ip), url.QueryEscape(mask), url.QueryEscape(gateway))
	_, err := s.get(path)
	return err
}

type LagGroup struct {
	ID    int
	Ports []int
}

// fetchLAG is best-effort: this device has no LAGs configured on the unit we
// tested against, so the parsing of portStr_g1..g8 below has not been
// verified against real non-empty data. See concerns.md.
func (s *Switch) fetchLAG() ([]LagGroup, error) {
	html, err := s.get("PortTrunkRpm.htm")
	if err != nil {
		return nil, err
	}
	var groups []LagGroup
	for g := 1; g <= 8; g++ {
		arr := splitCSVInts(extractArray(html, fmt.Sprintf("portStr_g%d", g)))
		var ports []int
		for i, v := range arr {
			if v != 0 {
				ports = append(ports, i+1)
			}
		}
		if len(ports) > 0 {
			groups = append(groups, LagGroup{ID: g, Ports: ports})
		}
	}
	return groups, nil
}

// --------------------------------------------------------- config backup/restore --
//
// This device has no "running-config" vs "startup-config" distinction of its
// own - every change is written to flash immediately. tpios fakes the
// distinction locally: "write memory" / "copy running-config startup-config"
// dumps the exact text `show running-config` produces to a local file;
// "copy startup-config running-config" reads it back and replays it against
// the device, the way a real switch loads its startup-config at boot. tpios
// also does that replay automatically at connect time if a backup exists for
// this switch's MAC, matching how real hardware behaves - not something it
// asks permission for, same as a real switch doesn't ask either.
//
// The parser below understands only tpios's own output, not arbitrary Cisco
// config syntax - that's deliberate: we don't need to parse everything IOS
// could show, just reliably round-trip what we ourselves generate.

func configDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "tpios"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "tpios"), nil
}

// backupConfigPath is keyed by MAC, not IP - this switch's IP can come from
// DHCP (and tpios can now change it via replay), so MAC is the only stable
// identity across sessions.
func backupConfigPath(mac string) (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	safe := strings.ToUpper(strings.NewReplacer(":", "", "-", "").Replace(mac))
	if safe == "" {
		safe = "unknown"
	}
	return filepath.Join(dir, safe+".cfg"), nil
}

type PortTarget struct {
	Shutdown       bool
	SpeedCfg       int // 1 = Auto, the default
	FlowControl    int
	Mode           string // "access", "trunk", or ""
	AccessVlan     int
	TrunkVlans     []int
	Description    string
	HasDescription bool
	pendingSpeed   string // holds "speed" until the following "duplex" line completes the pair
}

type ConfigTarget struct {
	Hostname       string
	HasIP          bool
	DHCP           bool
	IPAddr         string
	IPMask         string
	IPGateway      string
	LoopPrevention bool
	VlanNames      map[int]string
	Ports          map[int]*PortTarget
}

// parseConfigText understands exactly the dialect buildRunningConfig emits:
// unindented top-level directives and block headers ("hostname X", "vlan N",
// "interface GigabitEthernet0/N"), one-space-indented lines inside a block,
// and "!" or a blank line closing the current block.
func parseConfigText(text string) *ConfigTarget {
	cfg := &ConfigTarget{VlanNames: map[int]string{}, Ports: map[int]*PortTarget{}}
	var curPort *PortTarget
	var curVlanID int
	inVlan := false

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		indented := strings.HasPrefix(line, " ")

		if trimmed == "" || trimmed == "!" {
			inVlan = false
			curPort = nil
			continue
		}

		switch {
		case !indented && strings.HasPrefix(trimmed, "hostname "):
			cfg.Hostname = strings.TrimPrefix(trimmed, "hostname ")
		case !indented && strings.HasPrefix(trimmed, "ip address "):
			cfg.HasIP = true
			rest := strings.TrimPrefix(trimmed, "ip address ")
			if rest == "dhcp" {
				cfg.DHCP = true
			} else if parts := strings.Fields(rest); len(parts) >= 2 {
				cfg.IPAddr, cfg.IPMask = parts[0], parts[1]
			}
		case !indented && strings.HasPrefix(trimmed, "ip default-gateway "):
			cfg.IPGateway = strings.TrimPrefix(trimmed, "ip default-gateway ")
		case !indented && trimmed == "loop-detection":
			cfg.LoopPrevention = true
		case !indented && strings.HasPrefix(trimmed, "vlan "):
			if n, err := strconv.Atoi(strings.TrimPrefix(trimmed, "vlan ")); err == nil {
				curVlanID = n
				inVlan = true
				if _, ok := cfg.VlanNames[n]; !ok {
					cfg.VlanNames[n] = fmt.Sprintf("VLAN%d", n)
				}
			}
		case inVlan && indented && strings.HasPrefix(trimmed, "name "):
			cfg.VlanNames[curVlanID] = strings.TrimPrefix(trimmed, "name ")
		case !indented && strings.HasPrefix(trimmed, "interface GigabitEthernet0/"):
			if n, err := strconv.Atoi(strings.TrimPrefix(trimmed, "interface GigabitEthernet0/")); err == nil {
				curPort = &PortTarget{SpeedCfg: 1}
				cfg.Ports[n] = curPort
			}
		case !indented && strings.HasPrefix(trimmed, "interface Port-channel"):
			// LAG blocks are informational only - no write support, skip.
		case curPort != nil && indented:
			switch {
			case trimmed == "shutdown":
				curPort.Shutdown = true
			case strings.HasPrefix(trimmed, "speed "):
				curPort.pendingSpeed = strings.TrimPrefix(trimmed, "speed ")
			case strings.HasPrefix(trimmed, "duplex "):
				curPort.SpeedCfg = parseSpeedDuplex(curPort.pendingSpeed, strings.TrimPrefix(trimmed, "duplex "))
			case trimmed == "flowcontrol on":
				curPort.FlowControl = 1
			case trimmed == "switchport mode trunk":
				curPort.Mode = "trunk"
			case strings.HasPrefix(trimmed, "switchport trunk allowed vlan "):
				curPort.Mode = "trunk"
				for _, v := range strings.Split(strings.TrimPrefix(trimmed, "switchport trunk allowed vlan "), ",") {
					if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
						curPort.TrunkVlans = append(curPort.TrunkVlans, n)
					}
				}
			case strings.HasPrefix(trimmed, "switchport access vlan "):
				if n, err := strconv.Atoi(strings.TrimPrefix(trimmed, "switchport access vlan ")); err == nil {
					curPort.Mode = "access"
					curPort.AccessVlan = n
				}
			case strings.HasPrefix(trimmed, "description "):
				curPort.Description = strings.TrimPrefix(trimmed, "description ")
				curPort.HasDescription = true
			}
		}
	}
	return cfg
}

// parseSpeedDuplex is the inverse of speedLabel/duplexLabel.
func parseSpeedDuplex(speed, duplex string) int {
	switch speed {
	case "10":
		if duplex == "half" {
			return 2
		}
		return 3
	case "100":
		if duplex == "half" {
			return 4
		}
		return 5
	case "1000":
		return 6
	default:
		return 1 // auto
	}
}

// --------------------------------------------------------- device flash storage --
//
// This device has its own native config backup/restore feature: GET
// config_back.cgi downloads a small (~2.6KB on the TL-SG1024DE) proprietary
// binary blob of its NVRAM, and POSTing a file to conf_restore.cgi restores
// it, triggering an automatic reboot. The blob's layout was mapped by hand
// against this device's exact firmware (1.0.0 Build 20230616 Rel.34205) and
// is mostly fixed-size tables with a lot of genuinely-unused zero padding -
// reserved slots for VLANs/features that aren't configured. Verified live:
// writing our own data into that padding (leaving the real header, magic,
// and populated fields untouched) survives a full restore+reboot+reread
// cycle byte-for-byte, and the device stays completely healthy. Also
// verified: the magic header IS checked - corrupting it gets a clean
// "Failed" rejection with no reboot attempted, no corruption. So this only
// works starting from a real backup from the actual device, never from a
// synthetic blob built from nothing.
//
// This is exploiting an undocumented, unvalidated implementation detail of
// one specific firmware build. It is NOT guaranteed to be safe on a
// different model or even a different firmware revision of the same
// model - the padding we found here could be meaningful, live data on a
// different build. initStorage() refuses to run on an unrecognized
// hardware/firmware string without an explicit override, and independently
// re-discovers the usable region by scanning for the largest actual
// contiguous zero run (with a safety margin trimmed off both ends) rather
// than trusting a hardcoded offset - that at least adapts to a device with
// a similar layout but a different amount of real data before its padding
// starts. It is still a guess, not a guarantee.

var tpiosStorageMagic = []byte("TPC1")

const (
	storageHeaderLen  = 12  // magic(4) + regionTotalLen(4) + payloadLen(4)
	storageMargin     = 32  // bytes trimmed off each end of a newly-found zero run, in case our "it's all zero" read is slightly off at the edges
	storageMinPayload = 256 // below this, device storage isn't worth the reboot cost over just using the local file
)

var errNoStoredConfig = errors.New("no tpios data found in this switch's flash - run \"init storage\" first")

// knownGoodHardware is the exact hardwareStr this feature was verified
// against. initStorage() requires an explicit override to proceed on
// anything else - see the package comment above for why.
const knownGoodHardware = "TL-SG1024DE 7.0"

type storageRegion struct {
	start    int // offset of our magic within the backup blob
	totalLen int // full size of our allocated slot, including the header
}

// findStorageRegion looks for tpios's own magic already present in a
// downloaded backup - the normal case for every write after the first.
func findStorageRegion(backup []byte) (*storageRegion, bool) {
	idx := bytes.Index(backup, tpiosStorageMagic)
	if idx < 0 || idx+storageHeaderLen > len(backup) {
		return nil, false
	}
	regionLen := int(binary.LittleEndian.Uint32(backup[idx+4 : idx+8]))
	if regionLen < storageHeaderLen || idx+regionLen > len(backup) {
		return nil, false
	}
	return &storageRegion{start: idx, totalLen: regionLen}, true
}

// findLargestZeroRun scans for the biggest contiguous run of zero bytes in
// the backup and trims storageMargin off each end, used only the first time
// (no existing magic yet) to pick where to put our data.
func findLargestZeroRun(backup []byte) (start, length int, ok bool) {
	bestStart, bestLen := -1, 0
	curStart, curLen := -1, 0
	for i, b := range backup {
		if b == 0 {
			if curStart == -1 {
				curStart = i
			}
			curLen++
		} else {
			if curLen > bestLen {
				bestStart, bestLen = curStart, curLen
			}
			curStart, curLen = -1, 0
		}
	}
	if curLen > bestLen {
		bestStart, bestLen = curStart, curLen
	}
	if bestStart < 0 || bestLen <= 2*storageMargin {
		return 0, 0, false
	}
	return bestStart + storageMargin, bestLen - 2*storageMargin, true
}

func (s *Switch) fetchRawBackup() ([]byte, error) {
	if err := s.ensureSession(); err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", s.base+"/config_back.cgi", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("no response from switch (timeout) fetching backup: %w", err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// uploadRawBackup posts data as the restore file. A successful HTTP
// response here means the device accepted it and is rebooting - it does
// NOT mean the content was valid; this device answers magic-mismatch
// rejections as a normal 200 page containing tip:"Failed" rather than an
// HTTP error, so that has to be checked explicitly.
func (s *Switch) uploadRawBackup(data []byte) error {
	if err := s.ensureSession(); err != nil {
		return err
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("configfile", "config.cfg")
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	req, err := http.NewRequest("POST", s.base+"/conf_restore.cgi", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("no response from switch (timeout) during restore upload: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if bytes.Contains(respBody, []byte(`tip = "Failed"`)) {
		return fmt.Errorf("switch rejected the restore file (bad magic/format) - nothing was changed, no reboot triggered")
	}
	return nil
}

// waitForReboot polls plain GET / (no auth needed) until the switch
// answers again or the deadline passes. Login state on s is left stale
// deliberately - callers must re-login afterward, since the device's
// session almost certainly didn't survive the reboot.
func (s *Switch) waitForReboot(deadline time.Duration) error {
	start := time.Now()
	client := &http.Client{Timeout: 4 * time.Second}
	for time.Since(start) < deadline {
		time.Sleep(3 * time.Second)
		resp, err := client.Get(s.base + "/")
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			s.loggedIn = false
			return nil
		}
	}
	return fmt.Errorf("switch did not come back within %s after reboot", deadline)
}

// readStoredConfig downloads the backup, locates tpios's region, and
// decompresses the config text stored there.
func (s *Switch) readStoredConfig() (string, error) {
	backup, err := s.fetchRawBackup()
	if err != nil {
		return "", err
	}
	region, ok := findStorageRegion(backup)
	if !ok {
		return "", errNoStoredConfig
	}
	payloadLen := int(binary.LittleEndian.Uint32(backup[region.start+8 : region.start+12]))
	dataStart := region.start + storageHeaderLen
	if payloadLen < 0 || dataStart+payloadLen > region.start+region.totalLen || dataStart+payloadLen > len(backup) {
		return "", fmt.Errorf("stored config in flash looks corrupted (bad length field)")
	}
	r := flate.NewReader(bytes.NewReader(backup[dataStart : dataStart+payloadLen]))
	defer r.Close()
	text, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("stored config in flash failed to decompress: %w", err)
	}
	return string(text), nil
}

// writeStoredConfig compresses text and writes it into tpios's region in
// the device's own backup blob, creating that region (via
// findLargestZeroRun) if this is the first time. Always triggers a reboot
// on success - callers must re-login afterward.
func (s *Switch) writeStoredConfig(text string) error {
	backup, err := s.fetchRawBackup()
	if err != nil {
		return err
	}

	region, existing := findStorageRegion(backup)
	if !existing {
		start, length, ok := findLargestZeroRun(backup)
		if !ok || length < storageHeaderLen+storageMinPayload {
			return fmt.Errorf("no usable flash storage region found on this device - refusing (largest usable run: %d bytes, need at least %d)", length, storageHeaderLen+storageMinPayload)
		}
		region = &storageRegion{start: start, totalLen: length}
	}

	var compressed bytes.Buffer
	fw, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return err
	}
	if _, err := fw.Write([]byte(text)); err != nil {
		return err
	}
	if err := fw.Close(); err != nil {
		return err
	}
	if storageHeaderLen+compressed.Len() > region.totalLen {
		return fmt.Errorf("config too large for device flash storage: needs %d bytes, only %d available in this device's reserved slot - trim VLANs/descriptions, or just rely on the local backup file instead", storageHeaderLen+compressed.Len(), region.totalLen)
	}

	slot := make([]byte, region.totalLen) // zero-filled; unused tail stays zero
	copy(slot[0:4], tpiosStorageMagic)
	binary.LittleEndian.PutUint32(slot[4:8], uint32(region.totalLen))
	binary.LittleEndian.PutUint32(slot[8:12], uint32(compressed.Len()))
	copy(slot[storageHeaderLen:], compressed.Bytes())

	newBackup := make([]byte, len(backup))
	copy(newBackup, backup)
	copy(newBackup[region.start:region.start+region.totalLen], slot)

	if err := s.uploadRawBackup(newBackup); err != nil {
		return err
	}
	return s.waitForReboot(90 * time.Second)
}

// ---------------------------------------------------------------------- CLI --

type Mode int

const (
	ModeUser Mode = iota
	ModePriv
	ModeConfig
	ModeConfigIf
	ModeConfigVlan
)

type CLI struct {
	sw            *Switch
	mode          Mode
	hostname      string
	curIf         int
	curVlan       int
	pendingNames  map[int]string // vlan id -> name chosen before it has any port member (device can't persist an empty vlan)
	descriptions  map[int]string // port -> description; this device has no field for it, so it only ever lives here and in the backup file
	mac           string         // identifies the backup file for this switch (backupConfigPath)
	connectIP     string         // the IP this session dialed - used to detect a replay changing it out from under us
	out           *bufio.Writer
	rl            *readline.Instance // needed for the "copy start run" confirm prompt
	exitRequested bool               // set when a replay changes the IP/DHCP setting and this session's connection is now stale
}

func vlanDisplayName(vt *VlanTable, pending map[int]string, vid int) string {
	if v := vt.byID(vid); v != nil && v.Name != "" {
		return v.Name
	}
	if n, ok := pending[vid]; ok {
		return n
	}
	return fmt.Sprintf("VLAN%d", vid)
}

func (c *CLI) prompt() string {
	switch c.mode {
	case ModeUser:
		return c.hostname + ">"
	case ModePriv:
		return c.hostname + "#"
	case ModeConfig:
		return c.hostname + "(config)#"
	case ModeConfigIf:
		return c.hostname + "(config-if)#"
	case ModeConfigVlan:
		return c.hostname + "(config-vlan)#"
	}
	return "?"
}

func (c *CLI) printf(format string, a ...interface{}) {
	fmt.Fprintf(c.out, format, a...)
	c.out.Flush()
}

func (c *CLI) println(a ...interface{}) {
	fmt.Fprintln(c.out, a...)
	c.out.Flush()
}

func parseIfName(s string) (int, bool) {
	idx := strings.LastIndex(s, "/")
	numStr := s
	if idx >= 0 {
		numStr = s[idx+1:]
	}
	n, err := strconv.Atoi(numStr)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

func lc(s string) string { return strings.ToLower(s) }

func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func (c *CLI) showVersion() {
	si, err := c.sw.fetchSysInfo()
	if err != nil {
		c.println("%", err)
		return
	}
	c.printf("Cisco IOS Software, C2960DE Software (tpios-emulation), Version 15.2(2)E-ish\n")
	c.printf("tpios: a Go+HTTP shell over TP-Link EasySmart web UI\n\n")
	c.printf("%s uptime is unknown (device does not expose it)\n", c.hostname)
	c.printf("System description                 : %s\n", si.Desc)
	c.printf("System MAC Address                 : %s\n", si.MAC)
	c.printf("System IP Address                  : %s (%s, gw %s)\n", si.IP, si.Mask, si.Gateway)
	c.printf("Model number                       : %s\n", si.Hardware)
	c.printf("Software Version (vendor firmware) : %s\n", si.Firmware)
	c.printf("tpios version                      : %s\n", tpiosVersion())
}

// tpiosVersion identifies the running tpios build for bug reports. No
// semver yet - this reports "git-<short revision>" using the VCS info Go
// automatically embeds when building from a git checkout (no ldflags/
// Makefile wiring needed), with a "-dirty" suffix if the working tree had
// uncommitted changes at build time.
func tpiosVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "git-unknown"
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "git-unknown"
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if dirty {
		rev += "-dirty"
	}
	return "git-" + rev
}

func (c *CLI) showVlan() {
	vt, err := c.sw.fetchVlans()
	if err != nil {
		c.println("%", err)
		return
	}
	c.println("VLAN Name                             Status    Ports")
	c.println("---- -------------------------------- --------- -------------------------------------")
	if !vt.Enabled || len(vt.Vlans) == 0 {
		ports := make([]string, c.sw.portNum)
		for p := 1; p <= c.sw.portNum; p++ {
			ports[p-1] = fmt.Sprintf("Gi0/%d", p)
		}
		c.printf("%-4d %-34s %-9s %s\n", 1, "default", "active", strings.Join(ports, ", "))
		return
	}
	for _, v := range vt.Vlans {
		var ports []string
		for p := 1; p <= c.sw.portNum; p++ {
			if v.UntagMask&(1<<(p-1)) != 0 {
				ports = append(ports, fmt.Sprintf("Gi0/%d", p))
			}
		}
		c.printf("%-4d %-34s %-9s %s\n", v.ID, v.Name, "active", strings.Join(ports, ", "))
	}
}

func (c *CLI) showIntStatus() {
	ps, err := c.sw.fetchPortSettings()
	if err != nil {
		c.println("%", err)
		return
	}
	vt, err := c.sw.fetchVlans()
	if err != nil {
		c.println("%", err)
		return
	}
	pvids, err := c.sw.fetchPVIDs()
	if err != nil {
		c.println("%", err)
		return
	}
	c.printf("%-10s %-20s %-12s %-6s %-7s %-5s %s\n", "Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type")
	for p := 1; p <= c.sw.portNum; p++ {
		st := at(ps.State, p)
		act := at(ps.SpdAct, p)
		var status string
		switch {
		case st == 0:
			status = "disabled"
		case act == 0:
			status = "notconnect"
		default:
			status = "connected"
		}
		vlan := portVlanDisplay(vt, pvids, p)
		dup, spd := "--", "--"
		if act != 0 {
			dup, spd = duplexLabel(act), speedLabel(act)
		}
		name := c.descriptions[p]
		if len(name) > 20 { // real IOS hard-truncates this column too
			name = name[:20]
		}
		c.printf("Gi0/%-6d %-20s %-12s %-6s %-7s %-5s %s\n", p, name, status, vlan, dup, spd, "10/100/1000BaseTX")
	}
}

// speedDuplexPhrase matches real IOS's "show interfaces" wording for the
// configured speed/duplex line: "Auto-duplex, Auto-speed" when the port is
// set to auto-negotiate, else "<Full|Half>-duplex, <N>Mb/s" for a forced
// setting.
func speedDuplexPhrase(cfg int) string {
	if cfg == 1 {
		return "Auto-duplex, Auto-speed"
	}
	dup := "Full"
	if duplexLabel(cfg) == "half" {
		dup = "Half"
	}
	return fmt.Sprintf("%s-duplex, %sMb/s", dup, speedLabel(cfg))
}

// renderIntDetail mirrors a real 2960's "show interfaces" as closely as this
// hardware's own data honestly supports:
//   - status line, speed/duplex, flow control, packet counters: real device data
//   - hardware address: real, but it's this switch's one system-wide MAC
//     repeated for every port - the device exposes no per-port MAC
//   - input/output flow-control: the device has one combined setting, not
//     separate directions, so both lines show the same value
//   - MTU/BW/DLY/encapsulation/keepalive/the idle reliability-load baseline:
//     universal facts for any Ethernet switchport, true by spec rather than
//     device-specific guesses - not read from the device
//   - everything else real IOS shows (queue depths, CRC/runt/giant/collision
//     breakdowns, byte counts, last-input timestamps): omitted rather than
//     invented, since this device exposes none of it. See concerns.md.
func (c *CLI) renderIntDetail(ps *PortSettings, stats *PortStats, mac string, port int) {
	st, act, cfg, fc := at(ps.State, port), at(ps.SpdAct, port), at(ps.SpdCfg, port), at(ps.FcAct, port)
	adminState := "administratively down"
	if st == 1 {
		adminState = "up"
	}
	lineState := "down"
	status := "notconnect"
	switch {
	case st == 0:
		status = "disabled"
	case act != 0:
		lineState, status = "up", "connected"
	}
	c.printf("GigabitEthernet0/%d is %s, line protocol is %s (%s)\n", port, adminState, lineState, status)
	if desc, ok := c.descriptions[port]; ok && desc != "" {
		c.printf("  Description: %s\n", desc)
	}
	c.printf("  Hardware is Gigabit Ethernet, address is %s (bia %s)\n", mac, mac)
	c.println("  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,")
	c.println("     reliability 255/255, txload 1/255, rxload 1/255")
	c.println("  Encapsulation ARPA, loopback not set")
	c.println("  Keepalive not supported")
	// Once a link is up, show what it actually negotiated to, not the
	// configured policy - real IOS reports the negotiation outcome here,
	// and "Auto-duplex, Auto-speed" would otherwise silently hide a
	// degraded link (e.g. fallen back to 100Mb/s half-duplex) on any port
	// left at the default Auto setting, which is nearly all of them.
	speedDuplexCode := cfg
	if act != 0 {
		speedDuplexCode = act
	}
	c.printf("  %s, media type is 10/100/1000BaseTX\n", speedDuplexPhrase(speedDuplexCode))
	fcState := "off"
	if fc == 1 {
		fcState = "on"
	}
	c.printf("  input flow-control is %s, output flow-control is %s\n", fcState, fcState)
	if stats != nil {
		idx := port - 1
		if idx >= 0 && idx < len(stats.RxGood) {
			c.printf("     %d packets input, %d received in error\n", stats.RxGood[idx], stats.RxBad[idx])
			c.printf("     %d packets output, %d sent in error\n", stats.TxGood[idx], stats.TxBad[idx])
		}
	}
}

func (c *CLI) showIntOne(port int) {
	ps, err := c.sw.fetchPortSettings()
	if err != nil {
		c.println("%", err)
		return
	}
	stats, err := c.sw.fetchPortStats()
	if err != nil {
		c.println("%", err)
		return
	}
	si, err := c.sw.fetchSysInfo()
	mac := "00:00:00:00:00:00"
	if err == nil && si.MAC != "" {
		mac = si.MAC
	}
	c.renderIntDetail(ps, stats, mac, port)
}

// showIntAll is what real IOS gives for bare "show interfaces" - the same
// per-interface detail as showIntOne, for every port, fetched once rather
// than once per port.
func (c *CLI) showIntAll() {
	ps, err := c.sw.fetchPortSettings()
	if err != nil {
		c.println("%", err)
		return
	}
	stats, err := c.sw.fetchPortStats()
	if err != nil {
		c.println("%", err)
		return
	}
	si, err := c.sw.fetchSysInfo()
	mac := "00:00:00:00:00:00"
	if err == nil && si.MAC != "" {
		mac = si.MAC
	}
	for p := 1; p <= c.sw.portNum; p++ {
		if p > 1 {
			c.println()
		}
		c.renderIntDetail(ps, stats, mac, p)
	}
}

// buildRunningConfig is the single source of truth for tpios's Cisco-dialect
// config text - used by `show running-config`, `write memory` (which saves
// this exact text to the local backup file), and implicitly round-tripped by
// parseConfigText when that file is loaded back. Keep this and
// parseConfigText in sync: anything added here that should survive a
// save/restore cycle needs a matching case there.
func (c *CLI) buildRunningConfig() (string, error) {
	ps, err := c.sw.fetchPortSettings()
	if err != nil {
		return "", err
	}
	vt, err := c.sw.fetchVlans()
	if err != nil {
		return "", err
	}
	pvids, err := c.sw.fetchPVIDs()
	if err != nil {
		return "", err
	}
	ipset, err := c.sw.fetchIPSetting()
	if err != nil {
		return "", err
	}
	igmp, err := c.sw.fetchIgmpSnooping()
	if err != nil {
		return "", err
	}
	loopPrev, err := c.sw.fetchLoopPrevention()
	if err != nil {
		return "", err
	}
	lag, err := c.sw.fetchLAG()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintln(&b, "Building configuration...")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Current configuration:")
	fmt.Fprintln(&b, "!")
	fmt.Fprintf(&b, "hostname %s\n", c.hostname)
	fmt.Fprintln(&b, "!")
	if ipset.DHCP {
		fmt.Fprintln(&b, "ip address dhcp")
	} else {
		fmt.Fprintf(&b, "ip address %s %s\n", ipset.IP, ipset.Mask)
		if ipset.Gateway != "" {
			fmt.Fprintf(&b, "ip default-gateway %s\n", ipset.Gateway)
		}
	}
	if igmp {
		// Read-only in tpios - "copy start run" does not write this back.
		fmt.Fprintln(&b, "ip igmp snooping")
	}
	if loopPrev {
		// Not a real Cisco IOS command - this switch's "Loop Prevention"
		// toggle has no exact IOS equivalent. Named for plausibility; see
		// concerns.md. Unlike igmp snooping, this one IS written back by
		// "copy start run" (setLoopPrevention).
		fmt.Fprintln(&b, "loop-detection")
	}
	fmt.Fprintln(&b, "!")
	if vt.Enabled {
		for _, v := range vt.Vlans {
			if v.ID == 1 {
				continue
			}
			fmt.Fprintf(&b, "vlan %d\n", v.ID)
			fmt.Fprintf(&b, " name %s\n", v.Name)
			fmt.Fprintln(&b, "!")
		}
	}
	for _, g := range lag {
		var members []string
		for _, p := range g.Ports {
			members = append(members, fmt.Sprintf("Gi0/%d", p))
		}
		fmt.Fprintf(&b, "interface Port-channel%d\n", g.ID)
		fmt.Fprintf(&b, " ! members: %s\n", strings.Join(members, ", "))
		fmt.Fprintln(&b, "!")
	}
	for p := 1; p <= c.sw.portNum; p++ {
		fmt.Fprintf(&b, "interface GigabitEthernet0/%d\n", p)
		if desc, ok := c.descriptions[p]; ok && desc != "" {
			fmt.Fprintf(&b, " description %s\n", desc)
		}
		if at(ps.State, p) == 0 {
			fmt.Fprintln(&b, " shutdown")
		}
		if cfg := at(ps.SpdCfg, p); cfg != 1 { // 1 == Auto, the default
			fmt.Fprintf(&b, " speed %s\n", speedLabel(cfg))
			fmt.Fprintf(&b, " duplex %s\n", duplexLabel(cfg))
		}
		if at(ps.FcCfg, p) == 1 { // off is the default
			fmt.Fprintln(&b, " flowcontrol on")
		}
		vlan := portVlanDisplay(vt, pvids, p)
		if vlan == "trunk" {
			var allowed []string
			bit := 1 << (p - 1)
			for _, v := range vt.Vlans {
				if v.TagMask&bit != 0 {
					allowed = append(allowed, strconv.Itoa(v.ID))
				}
			}
			fmt.Fprintln(&b, " switchport mode trunk")
			if len(allowed) > 0 {
				fmt.Fprintf(&b, " switchport trunk allowed vlan %s\n", strings.Join(allowed, ","))
			}
		} else if vlan != "1" {
			fmt.Fprintf(&b, " switchport access vlan %s\n", vlan)
		}
		fmt.Fprintln(&b, "!")
	}
	fmt.Fprintln(&b, "end")
	return b.String(), nil
}

func (c *CLI) showRunningConfig() {
	text, err := c.buildRunningConfig()
	if err != nil {
		c.println("%", err)
		return
	}
	c.out.WriteString(text)
	c.out.Flush()
}

// saveConfig is "write memory" / "copy running-config startup-config" - the
// first real action either of those has ever done in tpios (previously just
// a canned "this device auto-persists" message, which is true of the device
// but says nothing about the local backup file).
// storageActive reports whether this switch's flash has already been
// claimed for tpios's own use (see the device flash storage section).
// Checked fresh every time rather than cached locally, so it works
// correctly regardless of which machine/session set it up.
func (c *CLI) storageActive() bool {
	backup, err := c.sw.fetchRawBackup()
	if err != nil {
		return false
	}
	_, ok := findStorageRegion(backup)
	return ok
}

// saveLocalCopy always writes the local backup file - this happens on
// every save regardless of device flash storage state, since it's free
// and gives a copy that doesn't require a working connection to retrieve.
func (c *CLI) saveLocalCopy(text string) (string, error) {
	path, err := backupConfigPath(c.mac)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (c *CLI) saveConfig() {
	text, err := c.buildRunningConfig()
	if err != nil {
		c.println("%", err)
		return
	}
	c.println("Building configuration...")
	path, err := c.saveLocalCopy(text)
	if err != nil {
		c.println("%", err)
		return
	}

	if !c.storageActive() {
		c.printf("[OK] (saved to %s)\n", path)
		return
	}

	c.printf("This switch's flash storage is initialized for tpios - saving there will reboot it (up to 90s). The local copy was saved either way. Continue? [confirm] ")
	line, _ := c.rl.Readline()
	if strings.TrimSpace(line) != "" {
		c.printf("Aborted. (local copy still saved to %s)\n", path)
		return
	}
	c.println("Writing to device flash and waiting for reboot...")
	if err := c.sw.writeStoredConfig(text); err != nil {
		c.println("%", err)
		return
	}
	if err := c.sw.login(); err != nil {
		c.println("%", err)
		c.println("The switch rebooted but tpios couldn't log back in automatically - reconnect manually.")
		c.exitRequested = true
		return
	}
	c.println("[OK] (saved to device flash storage)")
}

// applyIPSetting pushes an IP/DHCP change, filling in any blank field (a
// dhcp line, or a bare "ip default-gateway" command, carries no address of
// its own) from the device's current settings first. Returns whether the
// connection on c.sw might now be stale - see the isDialError comment below
// for why an error from the write itself still has to be treated as "maybe
// changed" rather than "didn't change". Shared by config replay and the
// interactive "ip address"/"ip default-gateway" commands.
// dhcp == nil means "keep whatever the device is currently set to" - used
// by "ip default-gateway", which must not force the device into static
// mode as a side effect of only touching the gateway.
func (c *CLI) applyIPSetting(dhcp *bool, ip, mask, gateway string) (changed bool) {
	// Reading current state first also lets a real DHCP<->static
	// transition (connection-breaking) be told apart from reapplying the
	// mode the device is already in (a no-op that still has to make the
	// cgi call, but must NOT be reported as having changed the IP - that
	// false positive used to make the boot-time loader quit immediately on
	// every switch already on DHCP, even though nothing changed).
	cur, curErr := c.sw.fetchIPSetting()
	effectiveDHCP := dhcp != nil && *dhcp
	if curErr == nil {
		if dhcp == nil {
			effectiveDHCP = cur.DHCP
		}
		if ip == "" {
			ip = cur.IP
		}
		if mask == "" {
			mask = cur.Mask
		}
		if gateway == "" {
			gateway = cur.Gateway
		}
	}
	if err := c.sw.setIPSetting(effectiveDHCP, ip, mask, gateway); err != nil {
		c.println("%", err)
		// Verified live: this specific call can time out client-side while
		// still succeeding on the device moments later (same slow-write
		// pattern documented for qvlan_en/device description in
		// concerns.md, now confirmed for IP too). A dial-stage error means
		// the request never reached the device, so nothing could have
		// changed; anything else is ambiguous, and for an IP-changing call
		// "ambiguous" must be treated as "assume changed" - letting the
		// session continue against a connection that might already be dead
		// is worse than an extra reconnect prompt.
		return !isDialError(err)
	}
	if curErr != nil {
		// Couldn't read the prior state to compare against - assume the
		// connection might now be stale rather than silently continuing to
		// hammer a possibly-dead address.
		return true
	}
	return effectiveDHCP != cur.DHCP || (!effectiveDHCP && ip != "" && ip != cur.IP)
}

// applyConfigTarget pushes a parsed config at the device, reusing the exact
// same methods the interactive commands use (switchportAccess and friends),
// so a replay behaves identically to someone typing the equivalent commands
// by hand. Returns true if the IP/DHCP setting was changed, which means
// every further request on c.sw will fail - callers must stop immediately
// and tell the user to reconnect rather than let subsequent calls time out
// confusingly against a now-dead address.
func (c *CLI) applyConfigTarget(cfg *ConfigTarget) (ipChanged bool) {
	if c.descriptions == nil {
		c.descriptions = map[int]string{}
	}
	for p, pt := range cfg.Ports {
		if pt.HasDescription {
			c.descriptions[p] = pt.Description
		}
	}

	if cfg.Hostname != "" && cfg.Hostname != c.hostname {
		if err := c.sw.setDeviceDescription(cfg.Hostname); err != nil {
			c.println("%", err)
		} else {
			c.hostname = cfg.Hostname
		}
	}

	// Pre-seed pendingNames so vlan auto-creation during switchport calls
	// below picks up the intended name instead of defaulting to "VLANxxx".
	if c.pendingNames == nil {
		c.pendingNames = map[int]string{}
	}
	for id, name := range cfg.VlanNames {
		c.pendingNames[id] = name
	}
	// Rename any of those vlans that already exist with a different name.
	if vt, err := c.sw.fetchVlans(); err == nil {
		for id, name := range cfg.VlanNames {
			if v := vt.byID(id); v != nil && v.Name != name {
				if err := c.sw.writeVlan(id, name, v.UntagMask, v.TagMask); err != nil {
					c.println("%", err)
				}
			}
		}
	}

	if err := c.sw.setLoopPrevention(cfg.LoopPrevention); err != nil {
		c.println("%", err)
	}

	// Read current port state so we can skip calls that would just reapply
	// what's already there. This matters beyond efficiency: reapplying
	// port_setting.cgi - even with unchanged values - can cause a brief PHY
	// renegotiation, and if that port happens to be the one carrying this
	// very management connection (very plausibly port 1, since that's
	// commonly the uplink port), the resulting HTTP response can be delayed
	// past our timeout. Observed live: a full replay consistently timed out
	// applying port 1's (already-correct) settings until this skip was added.
	curPS, _ := c.sw.fetchPortSettings()

	ports := make([]int, 0, len(cfg.Ports))
	for p := range cfg.Ports {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		pt := cfg.Ports[p]
		switch pt.Mode {
		case "access":
			c.switchportAccess(p, pt.AccessVlan)
		case "trunk":
			for _, v := range pt.TrunkVlans {
				c.switchportTrunkAdd(p, v)
			}
		}
		enabled := 1
		if pt.Shutdown {
			enabled = 0
		}
		if curPS != nil && at(curPS.State, p) == enabled && at(curPS.SpdCfg, p) == pt.SpeedCfg && at(curPS.FcCfg, p) == pt.FlowControl {
			continue // already matches - skip the call entirely
		}
		if err := c.sw.setPortState(p, enabled, pt.SpeedCfg, pt.FlowControl); err != nil {
			c.printf("%% port %d: %s\n", p, err)
		}
	}

	if cfg.HasIP {
		if c.applyIPSetting(&cfg.DHCP, cfg.IPAddr, cfg.IPMask, cfg.IPGateway) {
			ipChanged = true
		}
	}
	return ipChanged
}

// applyFromFile reads and replays path, returning whether the connection is
// now stale (see applyConfigTarget).
func (c *CLI) applyFromFile(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		c.println("%", err)
		return false
	}
	return c.applyConfigTarget(parseConfigText(string(data)))
}

func (c *CLI) applyFromText(text string) bool {
	return c.applyConfigTarget(parseConfigText(text))
}

// bootLoadIfPresent is the boot-time equivalent of a real switch loading its
// startup-config - unconditional, no confirmation. Checks device flash
// storage first (it's the more authoritative, device-resident copy if
// "init storage" has ever been run for this switch, from any machine),
// then the local backup file, then - if neither exists - runs the
// first-run setup prompt instead of silently doing nothing.
func (c *CLI) bootLoadIfPresent() {
	if c.storageActive() {
		c.bootLoadFromFlash()
		return
	}

	path, err := backupConfigPath(c.mac)
	if err == nil {
		if _, statErr := os.Stat(path); statErr == nil {
			c.printf("Loading backup configuration from %s...\n", path)
			if c.applyFromFile(path) {
				c.println("The switch's IP/DHCP setting just changed - this connection is now stale.")
				c.println("Reconnect once you know the new address.")
				c.exitRequested = true
			}
			return
		}
	}

	c.firstRunSetup()
}

// bootLoadFromFlash mirrors bootLoadIfPresent's local-file path, but
// sourcing from this switch's own flash storage instead.
func (c *CLI) bootLoadFromFlash() {
	text, err := c.sw.readStoredConfig()
	if err != nil {
		c.println("%", err)
		return
	}
	c.println("Loading backup configuration from this switch's own flash storage...")
	if c.applyFromText(text) {
		c.println("The switch's IP/DHCP setting just changed - this connection is now stale.")
		c.println("Reconnect once you know the new address.")
		c.exitRequested = true
	}
}

// firstRunSetup runs once per switch, the moment neither device flash
// storage nor a local backup file has anything for it yet - offers a
// choice instead of silently leaving persistence unconfigured.
func (c *CLI) firstRunSetup() {
	c.println()
	c.println("No tpios configuration found for this switch yet (checked its own flash storage and the local backup file).")
	c.println("How should tpios persist configuration for this switch going forward?")
	c.println(`  1. switch native - store it in this switch's own flash (runs "init storage" now - reboots the switch)`)
	c.println("  2. local         - a file on this machine only (~/.config/tpios/<MAC>.cfg, or $XDG_CONFIG_HOME if set)")
	c.println(`  3. skip          - decide later ("init storage" or "write memory" any time)`)
	c.printf("Choice [1/2/3, default 3]: ")
	line, _ := c.rl.Readline()
	switch strings.TrimSpace(strings.ToLower(line)) {
	case "1", "switch native", "native", "switch":
		c.initStorage()
	case "2", "local":
		text, err := c.buildRunningConfig()
		if err != nil {
			c.println("%", err)
			return
		}
		path, err := c.saveLocalCopy(text)
		if err != nil {
			c.println("%", err)
			return
		}
		c.printf("Saved initial local backup to %s\n", path)
	default:
		c.println(`Skipped - nothing persisted yet. Run "write memory" or "init storage" whenever you're ready.`)
	}
}

// copyStartToRun is the explicit "copy startup-config running-config"
// command - unlike bootLoadIfPresent, this happens mid-session on purpose,
// so it asks for confirmation first (it can silently undo live changes made
// since the backup was last saved).
func (c *CLI) copyStartToRun() {
	if c.storageActive() {
		c.printf("This will apply the configuration stored in this switch's own flash. Continue? [confirm] ")
		line, _ := c.rl.Readline()
		if strings.TrimSpace(line) != "" {
			c.println("Aborted.")
			return
		}
		text, err := c.sw.readStoredConfig()
		if err != nil {
			c.println("%", err)
			return
		}
		if c.applyFromText(text) {
			c.println("The switch's IP/DHCP setting just changed - this connection is now stale.")
			c.println("Reconnect once you know the new address.")
			c.exitRequested = true
		}
		return
	}

	path, err := backupConfigPath(c.mac)
	if err != nil {
		c.println("%", err)
		return
	}
	if _, err := os.Stat(path); err != nil {
		c.printf("%% No backup found at %s\n", path)
		return
	}
	c.printf("This will apply the configuration saved in %s to this switch. Continue? [confirm] ", path)
	line, _ := c.rl.Readline()
	if strings.TrimSpace(line) != "" {
		c.println("Aborted.")
		return
	}
	if c.applyFromFile(path) {
		c.println("The switch's IP/DHCP setting just changed - this connection is now stale.")
		c.println("Reconnect once you know the new address.")
		c.exitRequested = true
	}
}

// initStorage claims this switch's flash-backup slot for tpios's own use -
// see the device flash storage section for exactly what that means and its
// risks. Refuses to proceed on unrecognized hardware without an explicit
// override, since the padding this relies on was only verified on one
// specific firmware build.
func (c *CLI) initStorage() {
	si, err := c.sw.fetchSysInfo()
	if err != nil {
		c.println("%", err)
		return
	}
	if si.Hardware != knownGoodHardware {
		c.printf("%% This feature was only verified against hardware %q - this switch reports %q.\n", knownGoodHardware, si.Hardware)
		c.println("% Using it here is unverified and could corrupt real settings if this firmware's layout differs.")
		c.printf("Proceed anyway? [confirm] ")
		line, _ := c.rl.Readline()
		if strings.TrimSpace(line) != "" {
			c.println("Aborted.")
			return
		}
	}

	backup, err := c.sw.fetchRawBackup()
	if err != nil {
		c.println("%", err)
		return
	}
	if _, ok := findStorageRegion(backup); ok {
		c.println("This switch's flash storage is already initialized for tpios.")
		c.println(`Use "write memory" or "copy running-config startup-config" to update it.`)
		return
	}

	c.println(`This repurposes this switch's native "Backup and Restore" feature for tpios's own use.`)
	c.println("Afterward the switch's own web UI backup/restore will no longer produce anything meaningfully restorable elsewhere - tpios becomes the only tool that understands what's stored there.")
	c.println("This also triggers an immediate reboot.")
	c.printf("Continue? [confirm] ")
	line, _ := c.rl.Readline()
	if strings.TrimSpace(line) != "" {
		c.println("Aborted.")
		return
	}

	text, err := c.buildRunningConfig()
	if err != nil {
		c.println("%", err)
		return
	}
	c.println("Writing to device flash and waiting for reboot (this can take up to 90 seconds)...")
	if err := c.sw.writeStoredConfig(text); err != nil {
		c.println("%", err)
		return
	}
	if err := c.sw.login(); err != nil {
		c.println("%", err)
		c.println("The switch rebooted but tpios couldn't log back in automatically - reconnect manually.")
		c.exitRequested = true
		return
	}
	c.println(`Storage initialized. "write memory"/"wr" and "copy run start"/"copy start run" now operate on this switch's own flash (the local backup file is still kept too, as a free secondary copy).`)
}

// This hardware silently no-ops any VLAN create/update where every port is submitted
// as "not member" - a VLAN only persists once it has >=1 real tagged/untagged member.
// So we never write an empty membership set; every writeVlan call below includes the
// port bit that justifies the VLAN's existence. It also doesn't enforce untagged-VLAN
// exclusivity itself (a port can end up untagged in two VLANs at once), so switchportAccess
// explicitly clears the port's bit from every other VLAN's untagged mask.

func (c *CLI) switchportAccess(port, vid int) {
	vt, err := c.sw.fetchVlans()
	if err != nil {
		c.println("%", err)
		return
	}
	if err := c.sw.ensureQvlanEnabled(vt); err != nil {
		c.println("%", err)
		return
	}
	bit := 1 << (port - 1)
	target := vt.byID(vid)
	untag, tag := bit, 0
	if target != nil {
		untag = target.UntagMask | bit
		tag = target.TagMask &^ bit
	}
	name := vlanDisplayName(vt, c.pendingNames, vid)
	if err := c.sw.writeVlan(vid, name, untag, tag); err != nil {
		c.println("%", err)
		return
	}
	delete(c.pendingNames, vid)

	for _, v := range vt.Vlans {
		if v.ID == vid || v.UntagMask&bit == 0 {
			continue
		}
		newUntag := v.UntagMask &^ bit
		if err := c.sw.writeVlan(v.ID, v.Name, newUntag, v.TagMask); err != nil {
			c.println("%", err)
			return
		}
	}
	if err := c.sw.setPVID(port, vid); err != nil {
		c.println("%", err)
	}
}

func (c *CLI) switchportTrunkAdd(port, vid int) {
	vt, err := c.sw.fetchVlans()
	if err != nil {
		c.println("%", err)
		return
	}
	if err := c.sw.ensureQvlanEnabled(vt); err != nil {
		c.println("%", err)
		return
	}
	bit := 1 << (port - 1)
	target := vt.byID(vid)
	untag, tag := 0, bit
	if target != nil {
		untag = target.UntagMask &^ bit
		tag = target.TagMask | bit
	}
	name := vlanDisplayName(vt, c.pendingNames, vid)
	if err := c.sw.writeVlan(vid, name, untag, tag); err != nil {
		c.println("%", err)
		return
	}
	delete(c.pendingNames, vid)
}

func (c *CLI) noSwitchportVlan(port, vid int) {
	vt, err := c.sw.fetchVlans()
	if err != nil {
		c.println("%", err)
		return
	}
	v := vt.byID(vid)
	if v == nil {
		c.printf("%% VLAN %d does not exist\n", vid)
		return
	}
	bit := 1 << (port - 1)
	v.UntagMask &^= bit
	v.TagMask &^= bit
	if err := c.sw.writeVlan(v.ID, v.Name, v.UntagMask, v.TagMask); err != nil {
		c.println("%", err)
	}
}

func (c *CLI) printHelp() {
	c.println(`Commands (not exhaustive - this is a toy):
  enable | disable
  configure terminal
    interface gigabitEthernet0/<1-N>
      description <text> / no description
      shutdown / no shutdown
      switchport mode {access|trunk}
      switchport access vlan <id>
      switchport trunk allowed vlan [add] <id>
      no switchport access vlan <id> | no switchport trunk allowed vlan <id>
      speed {auto|10|100|1000}
      flowcontrol {on|off}
      exit / end
    vlan <id>
      name <name>
      exit / end
    no vlan <id>
    ip address {dhcp|<address> <mask>}
    ip default-gateway <address>
    init storage
    hostname <name>
    exit / end
  show version
  show vlan [brief]
  show interfaces status
  show interface gigabitEthernet0/<n>
  show running-config
  write memory | copy running-config startup-config  (local backup file, unless "init storage" ran)
  copy startup-config running-config                 (replays it onto this switch)
  clear counters
  exit / logout
Tab completes commands; a line ending in "?" lists what can come next.`)
}

func (c *CLI) dispatchShow(args []string) {
	switch lc(arg(args, 0)) {
	case "ver", "version":
		c.showVersion()
	case "vlan":
		c.showVlan()
	case "int", "interface", "interfaces":
		switch lc(arg(args, 1)) {
		case "status":
			c.showIntStatus()
		case "":
			// Real IOS: bare "show interfaces" means a detailed report for
			// every interface, as opposed to the compact "show interfaces
			// status" table above.
			c.showIntAll()
		default:
			if n, ok := parseIfName(arg(args, 1)); ok && n <= c.sw.portNum {
				c.showIntOne(n)
			} else {
				c.printf("%% Invalid interface: %s\n", arg(args, 1))
			}
		}
	case "run", "running-config":
		c.showRunningConfig()
	case "mac", "mac-address-table":
		c.println("% This command is not supported on this platform.")
	default:
		c.printf("%% Unknown show command: %s\n", arg(args, 0))
	}
}

// resolveAbbrev expands cmd to the one top-level candidate it's an
// unambiguous prefix of, reusing completionCandidates (the same list Tab
// already completes against) rather than requiring every command to have
// its abbreviations hand-enumerated as extra case labels. That hand
// enumeration is how "en"/"ena"/"enab"/"enable" all ended up working while
// "description" and "end" (in config-if mode, abbreviated as "en") didn't -
// nobody had added their short forms. Ambiguous or no-match prefixes are
// returned unchanged, so the existing "% Unknown command" handling still
// fires correctly - this only ever resolves a command that would already
// Tab-complete cleanly to exactly one thing.
func resolveAbbrev(mode Mode, cmd string) string {
	for _, cand := range completionCandidates(mode, nil) {
		if cand == cmd {
			return cmd
		}
	}
	match, count := "", 0
	for _, cand := range completionCandidates(mode, nil) {
		if strings.HasPrefix(cand, cmd) {
			match = cand
			count++
		}
	}
	if count == 1 {
		return match
	}
	return cmd
}

func (c *CLI) handleLine(line string) (quit bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	cmd := resolveAbbrev(c.mode, lc(fields[0]))
	args := fields[1:]

	switch c.mode {
	case ModeUser:
		switch cmd {
		case "en", "ena", "enab", "enable":
			c.mode = ModePriv
		case "sh", "show":
			c.dispatchShow(args)
		case "exit", "logout", "quit":
			c.println("Connection closed.")
			return true
		case "?", "help":
			c.printHelp()
		default:
			c.printf("%% Unknown command or ambiguous command: %q\n", fields[0])
		}

	case ModePriv:
		switch cmd {
		case "conf", "config", "configure":
			a0 := lc(arg(args, 0))
			if a0 == "" || a0 == "terminal" || a0 == "t" {
				c.mode = ModeConfig
			} else {
				c.println("% Unknown configure target")
			}
		case "sh", "show":
			c.dispatchShow(args)
		case "wr", "write":
			if a0 := lc(arg(args, 0)); a0 != "" && a0 != "memory" && a0 != "mem" {
				c.println("% Usage: write memory")
				break
			}
			c.saveConfig()
		case "copy":
			src, dst := lc(arg(args, 0)), lc(arg(args, 1))
			isRun := func(s string) bool { return s == "running-config" || s == "run" }
			isStart := func(s string) bool { return s == "startup-config" || s == "start" }
			switch {
			case isRun(src) && isStart(dst):
				c.saveConfig()
			case isStart(src) && isRun(dst):
				c.copyStartToRun()
			default:
				c.println("% Usage: copy running-config startup-config | copy startup-config running-config")
			}
		case "reload":
			c.println("Proceed with reload? [confirm]")
			c.println("% reload is disabled in tpios for safety - power-cycle the switch physically if needed")
		case "clear":
			if lc(arg(args, 0)) != "counters" {
				c.println("% Usage: clear counters")
				break
			}
			if len(args) > 1 {
				c.println("% This device clears counters for all ports at once - per-interface clear is not supported")
				break
			}
			if err := c.sw.clearPortStats(); err != nil {
				c.println("%", err)
			} else {
				c.println("Clear \"show interface\" counters on all interfaces [confirm]")
			}
		case "disable":
			c.mode = ModeUser
		case "exit", "logout":
			c.mode = ModeUser
		case "?", "help":
			c.printHelp()
		default:
			c.printf("%% Unknown command or ambiguous command: %q\n", fields[0])
		}

	case ModeConfig:
		switch cmd {
		case "int", "interface":
			if lc(arg(args, 0)) == "range" {
				c.println("% interface range is not supported in tpios yet")
			} else if n, ok := parseIfName(arg(args, 0)); ok && n <= c.sw.portNum {
				c.curIf = n
				c.mode = ModeConfigIf
			} else {
				c.printf("%% Invalid interface: %s\n", arg(args, 0))
			}
		case "vlan":
			vid, err := strconv.Atoi(arg(args, 0))
			if err != nil || vid < 1 {
				c.printf("%% Invalid VLAN id: %s\n", arg(args, 0))
			} else {
				c.curVlan = vid
				c.mode = ModeConfigVlan
			}
		case "no":
			if lc(arg(args, 0)) == "vlan" {
				vid, err := strconv.Atoi(arg(args, 1))
				if err != nil {
					c.printf("%% Invalid VLAN id: %s\n", arg(args, 1))
					break
				}
				vt, ferr := c.sw.fetchVlans()
				if ferr != nil {
					c.println("%", ferr)
					break
				}
				if vt.byID(vid) == nil {
					if _, pending := c.pendingNames[vid]; pending {
						delete(c.pendingNames, vid)
						c.printf("VLAN %d deleted\n", vid)
					} else {
						c.printf("%% VLAN %d does not exist\n", vid)
					}
				} else if err := c.sw.deleteVlan(vid); err != nil {
					c.println("%", err)
				} else {
					delete(c.pendingNames, vid)
					c.printf("VLAN %d deleted\n", vid)
				}
			} else {
				c.println("% Unknown 'no' command in config mode")
			}
		case "init":
			if lc(arg(args, 0)) != "storage" {
				c.println("% Usage: init storage")
				break
			}
			c.initStorage()
		case "ip":
			switch lc(arg(args, 0)) {
			case "address":
				var dhcp bool
				var ip, mask string
				if lc(arg(args, 1)) == "dhcp" {
					dhcp = true
				} else if arg(args, 2) != "" {
					ip, mask = arg(args, 1), arg(args, 2)
				} else {
					c.println("% Usage: ip address dhcp | ip address <address> <mask>")
					break
				}
				if c.applyIPSetting(&dhcp, ip, mask, "") {
					c.println("The switch's IP/DHCP setting just changed - this connection is now stale.")
					c.println("Reconnect once you know the new address.")
					c.exitRequested = true
				}
			case "default-gateway":
				gw := arg(args, 1)
				if gw == "" {
					c.println("% Usage: ip default-gateway <address>")
					break
				}
				if c.applyIPSetting(nil, "", "", gw) {
					c.println("The switch's IP/DHCP setting just changed - this connection is now stale.")
					c.println("Reconnect once you know the new address.")
					c.exitRequested = true
				}
			default:
				c.println("% Usage: ip address {dhcp|<address> <mask>} | ip default-gateway <address>")
			}
		case "hostname":
			name := arg(args, 0)
			if name == "" {
				c.println("% Missing hostname")
			} else if err := c.sw.setDeviceDescription(name); err != nil {
				c.println("%", err)
			} else {
				c.hostname = name
			}
		case "do":
			if lc(arg(args, 0)) == "show" {
				c.dispatchShow(args[1:])
			} else {
				c.println("% 'do' only supports show in tpios")
			}
		case "exit", "end":
			c.mode = ModePriv
		case "?", "help":
			c.printHelp()
		default:
			c.printf("%% Unknown command or ambiguous command: %q\n", fields[0])
		}

	case ModeConfigIf:
		switch cmd {
		case "description":
			if len(args) == 0 {
				c.println("% Usage: description <text>")
				break
			}
			if c.descriptions == nil {
				c.descriptions = map[int]string{}
			}
			c.descriptions[c.curIf] = strings.Join(args, " ")
		case "shutdown":
			ps, err := c.sw.fetchPortSettings()
			if err != nil {
				c.println("%", err)
				break
			}
			if err := c.sw.setPortState(c.curIf, 0, at(ps.SpdCfg, c.curIf), at(ps.FcCfg, c.curIf)); err != nil {
				c.println("%", err)
			} else {
				c.printf("%%LINK-5-CHANGED: Interface GigabitEthernet0/%d, changed state to administratively down\n", c.curIf)
			}
		case "no":
			switch lc(arg(args, 0)) {
			case "shutdown":
				ps, err := c.sw.fetchPortSettings()
				if err != nil {
					c.println("%", err)
					break
				}
				if err := c.sw.setPortState(c.curIf, 1, at(ps.SpdCfg, c.curIf), at(ps.FcCfg, c.curIf)); err != nil {
					c.println("%", err)
				} else {
					c.printf("%%LINK-3-UPDOWN: Interface GigabitEthernet0/%d, changed state to up\n", c.curIf)
				}
			case "switchport":
				switch lc(arg(args, 1)) {
				case "access":
					if vid, err := strconv.Atoi(arg(args, 3)); err == nil {
						c.noSwitchportVlan(c.curIf, vid)
					} else {
						c.println("% Usage: no switchport access vlan <id>")
					}
				case "trunk":
					if vid, err := strconv.Atoi(arg(args, 4)); err == nil {
						c.noSwitchportVlan(c.curIf, vid)
					} else {
						c.println("% Usage: no switchport trunk allowed vlan <id>")
					}
				default:
					c.println("% Usage: no switchport access vlan <id> | no switchport trunk allowed vlan <id>")
				}
			case "description":
				delete(c.descriptions, c.curIf)
			default:
				c.println("% Unknown 'no' command in interface mode")
			}
		case "switchport":
			switch lc(arg(args, 0)) {
			case "mode":
				switch lc(arg(args, 1)) {
				case "access", "trunk":
					// mode is tracked implicitly by subsequent access/trunk commands; nothing to persist.
				default:
					c.println("% Usage: switchport mode {access|trunk}")
				}
			case "access":
				if lc(arg(args, 1)) == "vlan" {
					if vid, err := strconv.Atoi(arg(args, 2)); err == nil {
						c.switchportAccess(c.curIf, vid)
					} else {
						c.println("% Usage: switchport access vlan <id>")
					}
				} else {
					c.println("% Usage: switchport access vlan <id>")
				}
			case "trunk":
				if lc(arg(args, 1)) == "allowed" && lc(arg(args, 2)) == "vlan" {
					v := arg(args, 3)
					if lc(v) == "add" {
						v = arg(args, 4)
					}
					if vid, err := strconv.Atoi(v); err == nil {
						c.switchportTrunkAdd(c.curIf, vid)
					} else {
						c.println("% Usage: switchport trunk allowed vlan [add] <id>")
					}
				} else {
					c.println("% Usage: switchport trunk allowed vlan [add] <id>")
				}
			default:
				c.println("% Usage: switchport mode|access|trunk ...")
			}
		case "speed":
			ps, err := c.sw.fetchPortSettings()
			if err != nil {
				c.println("%", err)
				break
			}
			var code int
			switch lc(arg(args, 0)) {
			case "auto":
				code = 1
			case "10":
				code = 3
			case "100":
				code = 5
			case "1000":
				code = 6
			default:
				c.println("% Usage: speed {auto|10|100|1000}")
				break
			}
			if code != 0 {
				if err := c.sw.setPortState(c.curIf, at(ps.State, c.curIf), code, at(ps.FcCfg, c.curIf)); err != nil {
					c.println("%", err)
				}
			}
		case "flowcontrol":
			ps, err := c.sw.fetchPortSettings()
			if err != nil {
				c.println("%", err)
				break
			}
			var fc int
			switch lc(arg(args, 0)) {
			case "on":
				fc = 1
			case "off":
				fc = 0
			default:
				c.println("% Usage: flowcontrol {on|off}")
				break
			}
			if err := c.sw.setPortState(c.curIf, at(ps.State, c.curIf), at(ps.SpdCfg, c.curIf), fc); err != nil {
				c.println("%", err)
			}
		case "exit":
			c.mode = ModeConfig
			c.curIf = 0
		case "end":
			c.mode = ModePriv
			c.curIf = 0
		case "?", "help":
			c.printHelp()
		default:
			c.printf("%% Unknown command or ambiguous command: %q\n", fields[0])
		}

	case ModeConfigVlan:
		switch cmd {
		case "name":
			name := arg(args, 0)
			vt, err := c.sw.fetchVlans()
			if err != nil {
				c.println("%", err)
				break
			}
			v := vt.byID(c.curVlan)
			if v == nil {
				// This hardware can't persist a VLAN with zero port members yet.
				// Remember the name; it's applied for real once a port is assigned
				// to this VLAN via switchport access/trunk.
				if c.pendingNames == nil {
					c.pendingNames = map[int]string{}
				}
				c.pendingNames[c.curVlan] = name
				c.printf("%% Note: VLAN %d has no ports yet, so this switch can't store it until one is assigned (switchport access/trunk); name %q remembered for then\n", c.curVlan, name)
				break
			}
			if err := c.sw.writeVlan(c.curVlan, name, v.UntagMask, v.TagMask); err != nil {
				c.println("%", err)
			}
		case "shutdown", "no":
			c.println("% VLAN admin state is not configurable on this platform; ignored")
		case "exit":
			c.mode = ModeConfig
			c.curVlan = 0
		case "end":
			c.mode = ModePriv
			c.curVlan = 0
		case "?", "help":
			c.printHelp()
		default:
			c.printf("%% Unknown command or ambiguous command: %q\n", fields[0])
		}
	}
	return false
}

// ------------------------------------------------------------- completion --

// completionCandidates returns the words that could legally follow
// precedingFields in the given mode. It's deliberately shallow (first and
// occasionally second word) rather than a full command grammar - enough for
// Tab and "?" to be useful without trying to model every argument.
func completionCandidates(mode Mode, precedingFields []string) []string {
	if len(precedingFields) == 0 {
		switch mode {
		case ModeUser:
			return []string{"enable", "show", "exit", "logout", "help"}
		case ModePriv:
			return []string{"configure", "show", "write", "copy", "clear", "reload", "disable", "exit", "logout", "help"}
		case ModeConfig:
			return []string{"interface", "vlan", "no", "ip", "hostname", "init", "do", "exit", "end", "help"}
		case ModeConfigIf:
			return []string{"description", "shutdown", "no", "switchport", "speed", "flowcontrol", "exit", "end", "help"}
		case ModeConfigVlan:
			return []string{"name", "shutdown", "no", "exit", "end", "help"}
		}
		return nil
	}
	first := lc(precedingFields[0])
	switch {
	case (first == "show" || first == "sh") && len(precedingFields) == 1:
		return []string{"version", "vlan", "interfaces", "interface", "running-config"}
	case (first == "show" || first == "sh") && len(precedingFields) == 2 &&
		(lc(precedingFields[1]) == "int" || lc(precedingFields[1]) == "interface" || lc(precedingFields[1]) == "interfaces"):
		// Real IOS also lists interface-type keywords here (GigabitEthernet,
		// Vlan, Port-channel, ...) that you'd keep typing a specific number
		// onto - skipped here since our completer assumes complete,
		// space-terminated words, and a bare number prefix doesn't fit that.
		return []string{"status"}
	case (first == "configure" || first == "conf") && len(precedingFields) == 1:
		return []string{"terminal"}
	case first == "switchport" && len(precedingFields) == 1:
		return []string{"mode", "access", "trunk"}
	case first == "switchport" && len(precedingFields) == 2 && lc(precedingFields[1]) == "mode":
		return []string{"access", "trunk"}
	case first == "no" && len(precedingFields) == 1 && mode == ModeConfig:
		return []string{"vlan"}
	case first == "no" && len(precedingFields) == 1 && mode == ModeConfigIf:
		return []string{"shutdown", "switchport", "description"}
	case first == "speed" && len(precedingFields) == 1:
		return []string{"auto", "10", "100", "1000"}
	case first == "flowcontrol" && len(precedingFields) == 1:
		return []string{"on", "off"}
	case first == "do" && len(precedingFields) == 1:
		return []string{"show"}
	case first == "clear" && len(precedingFields) == 1:
		return []string{"counters"}
	case first == "copy" && len(precedingFields) == 1:
		return []string{"running-config", "startup-config"}
	case first == "copy" && len(precedingFields) == 2 && lc(precedingFields[1]) == "running-config":
		return []string{"startup-config"}
	case first == "copy" && len(precedingFields) == 2 && lc(precedingFields[1]) == "startup-config":
		return []string{"running-config"}
	case first == "ip" && len(precedingFields) == 1:
		return []string{"address", "default-gateway"}
	case first == "ip" && len(precedingFields) == 2 && lc(precedingFields[1]) == "address":
		return []string{"dhcp"}
	case first == "init" && len(precedingFields) == 1:
		return []string{"storage"}
	}
	return nil
}

type cliCompleter struct {
	cli *CLI
}

func (cc *cliCompleter) Do(line []rune, pos int) ([][]rune, int) {
	text := string(line[:pos])
	trailingSpace := strings.HasSuffix(text, " ")
	fields := strings.Fields(text)
	var prefix string
	if !trailingSpace && len(fields) > 0 {
		prefix = fields[len(fields)-1]
		fields = fields[:len(fields)-1]
	}
	candidates := completionCandidates(cc.cli.mode, fields)
	var out [][]rune
	for _, cand := range candidates {
		if strings.HasPrefix(cand, lc(prefix)) {
			out = append(out, []rune(cand[len(prefix):]+" "))
		}
	}
	return out, len([]rune(prefix))
}

// showLineHelp implements the "?" help convention: a line ending in "?"
// (handled before it reaches handleLine) lists what can legally come next,
// the way Cisco IOS's inline "?" does - approximated at the line level
// rather than instant-keystroke, since that needs raw terminal interception
// we don't do here.
func (c *CLI) showLineHelp(prefixText string) {
	trailingSpace := strings.HasSuffix(prefixText, " ")
	fields := strings.Fields(prefixText)
	var lastWord string
	if !trailingSpace && len(fields) > 0 {
		lastWord = lc(fields[len(fields)-1])
		fields = fields[:len(fields)-1]
	}
	candidates := completionCandidates(c.mode, fields)
	var matched []string
	for _, cand := range candidates {
		if lastWord == "" || strings.HasPrefix(cand, lastWord) {
			matched = append(matched, cand)
		}
	}
	if len(matched) == 0 {
		c.println("% No matching commands")
		return
	}
	for _, cand := range matched {
		c.println("  " + cand)
	}
}

// ------------------------------------------------------------------- main() --

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-ports N] <switch-ip>\n", os.Args[0])
	}
	portNum := flag.Int("ports", 24, "number of switch ports")
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	ip := flag.Arg(0)

	const maxLoginAttempts = 3
	var sw *Switch
	for attempt := 1; ; attempt++ {
		user, err := readline.Line("Username: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "input error:", err)
			os.Exit(1)
		}
		user = strings.TrimSpace(user)

		passBytes, err := readline.Password("Password: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "input error:", err)
			os.Exit(1)
		}
		pass := strings.TrimSpace(string(passBytes))

		sw = NewSwitch(ip, user, pass, *portNum)
		fmt.Printf("Connecting to %s ...\n", ip)
		err = sw.login()
		if err == nil {
			break
		}

		var rejected *loginRejectedError
		if !errors.As(err, &rejected) {
			// Not a credential rejection (network/device-availability issue) -
			// re-asking for a password won't help, so just report and exit.
			fmt.Fprintln(os.Stderr, "Could not reach/login to", sw.base, "-", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "%", err)
		if attempt >= maxLoginAttempts {
			fmt.Fprintln(os.Stderr, "Too many failed login attempts.")
			os.Exit(1)
		}
		fmt.Println()
	}

	hostname := "Switch"
	mac := ""
	if si, err := sw.fetchSysInfo(); err == nil {
		if si.Desc != "" {
			hostname = si.Desc
		}
		mac = si.MAC
	}

	cli := &CLI{sw: sw, mode: ModeUser, hostname: hostname, mac: mac, connectIP: ip}

	var histFile string
	if home, err := os.UserHomeDir(); err == nil {
		histFile = filepath.Join(home, ".tpios_history")
	}

	// Real IOS shows "?" help the instant the key is pressed, no Enter
	// needed. chzyer/readline's Listener fires after the key is already
	// inserted into the buffer, so we strip it back out, print the help,
	// and force a redraw - rl is assigned just below, but by the time this
	// closure actually runs (on a real keypress) it's long since set.
	var rl *readline.Instance
	qListener := readline.FuncListener(func(line []rune, pos int, key rune) ([]rune, int, bool) {
		if key != '?' || pos < 1 {
			return nil, 0, false
		}
		before := append([]rune{}, line[:pos-1]...)
		before = append(before, line[pos:]...)
		fmt.Fprintln(cli.out)
		cli.showLineHelp(string(before))
		if rl != nil {
			rl.Refresh()
		}
		return before, pos - 1, true
	})

	var err error
	rl, err = readline.NewEx(&readline.Config{
		Prompt:       cli.prompt() + " ",
		HistoryFile:  histFile,
		AutoComplete: &cliCompleter{cli: cli},
		Listener:     qListener,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "readline init failed:", err)
		os.Exit(1)
	}
	defer rl.Close()
	cli.out = bufio.NewWriter(rl.Stdout())
	cli.rl = rl

	defer sw.logout()

	// Mirrors a real switch loading its own startup-config at boot - no
	// confirmation, silent if nothing has been saved yet for this MAC.
	cli.bootLoadIfPresent()
	if cli.exitRequested {
		return
	}

	fmt.Fprintln(rl.Stdout())
	fmt.Fprintln(rl.Stdout(), "User Access Verification")
	fmt.Fprintln(rl.Stdout())
	fmt.Fprintf(rl.Stdout(), "%s con0 is now available\n", cli.hostname)
	fmt.Fprintln(rl.Stdout(), "Press RETURN to get started.")
	fmt.Fprintln(rl.Stdout())

	for {
		rl.SetPrompt(cli.prompt() + " ")
		line, err := rl.Readline()
		if err != nil { // io.EOF (Ctrl-D) or readline.ErrInterrupt (Ctrl-C)
			fmt.Fprintln(rl.Stdout())
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasSuffix(line, "?") {
			cli.showLineHelp(strings.TrimSuffix(line, "?"))
			continue
		}
		if cli.handleLine(line) || cli.exitRequested {
			break
		}
	}
	fmt.Fprintln(rl.Stdout(), "Connection closed.")
}
