// tpios: a Cisco-2960-ish IOS shell for TP-Link EasySmart switches (TL-SG1024DE etc).
// There is no JSON API on these devices - this drives the same *.cgi/*.htm endpoints
// the browser's web UI uses, reverse-engineered by inspecting the real pages.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
	sw           *Switch
	mode         Mode
	hostname     string
	curIf        int
	curVlan      int
	pendingNames map[int]string // vlan id -> name chosen before it has any port member (device can't persist an empty vlan)
	out          *bufio.Writer
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
	c.printf("%-10s %-12s %-6s %-7s %-5s %s\n", "Port", "Status", "Vlan", "Duplex", "Speed", "Type")
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
		c.printf("Gi0/%-6d %-12s %-6s %-7s %-5s %s\n", p, status, vlan, dup, spd, "10/100/1000BaseTX")
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
	c.printf("  Hardware is Gigabit Ethernet, address is %s (bia %s)\n", mac, mac)
	c.println("  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,")
	c.println("     reliability 255/255, txload 1/255, rxload 1/255")
	c.println("  Encapsulation ARPA, loopback not set")
	c.println("  Keepalive not supported")
	c.printf("  %s, media type is 10/100/1000BaseTX\n", speedDuplexPhrase(cfg))
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

func (c *CLI) showRunningConfig() {
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
	ipset, err := c.sw.fetchIPSetting()
	if err != nil {
		c.println("%", err)
		return
	}
	igmp, err := c.sw.fetchIgmpSnooping()
	if err != nil {
		c.println("%", err)
		return
	}
	loopPrev, err := c.sw.fetchLoopPrevention()
	if err != nil {
		c.println("%", err)
		return
	}
	lag, err := c.sw.fetchLAG()
	if err != nil {
		c.println("%", err)
		return
	}

	c.println("Building configuration...")
	c.println()
	c.println("Current configuration:")
	c.println("!")
	c.printf("hostname %s\n", c.hostname)
	c.println("!")
	if ipset.DHCP {
		c.println("ip address dhcp")
	} else {
		c.printf("ip address %s %s\n", ipset.IP, ipset.Mask)
		if ipset.Gateway != "" {
			c.printf("ip default-gateway %s\n", ipset.Gateway)
		}
	}
	if igmp {
		c.println("ip igmp snooping")
	}
	if loopPrev {
		// Not a real Cisco IOS command - this switch's "Loop Prevention"
		// toggle has no exact IOS equivalent. Named for plausibility; see
		// concerns.md.
		c.println("loop-detection")
	}
	c.println("!")
	if vt.Enabled {
		for _, v := range vt.Vlans {
			if v.ID == 1 {
				continue
			}
			c.printf("vlan %d\n", v.ID)
			c.printf(" name %s\n", v.Name)
			c.println("!")
		}
	}
	for _, g := range lag {
		var members []string
		for _, p := range g.Ports {
			members = append(members, fmt.Sprintf("Gi0/%d", p))
		}
		c.printf("interface Port-channel%d\n", g.ID)
		c.printf(" ! members: %s\n", strings.Join(members, ", "))
		c.println("!")
	}
	for p := 1; p <= c.sw.portNum; p++ {
		c.printf("interface GigabitEthernet0/%d\n", p)
		if at(ps.State, p) == 0 {
			c.println(" shutdown")
		}
		if cfg := at(ps.SpdCfg, p); cfg != 1 { // 1 == Auto, the default
			c.printf(" speed %s\n", speedLabel(cfg))
			c.printf(" duplex %s\n", duplexLabel(cfg))
		}
		if at(ps.FcCfg, p) == 1 { // off is the default
			c.println(" flowcontrol on")
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
			c.println(" switchport mode trunk")
			if len(allowed) > 0 {
				c.printf(" switchport trunk allowed vlan %s\n", strings.Join(allowed, ","))
			}
		} else if vlan != "1" {
			c.printf(" switchport access vlan %s\n", vlan)
		}
		c.println("!")
	}
	c.println("end")
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
    hostname <name>
    exit / end
  show version
  show vlan [brief]
  show interfaces status
  show interface gigabitEthernet0/<n>
  show running-config
  write memory | copy running-config startup-config
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

func (c *CLI) handleLine(line string) (quit bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	cmd := lc(fields[0])
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
			c.println("Building configuration...")
			c.println("[OK] (note: this device auto-persists each change; there is no separate running/startup config)")
		case "copy":
			c.println("[OK] (note: this device auto-persists each change; there is no separate running/startup config)")
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
			return []string{"interface", "vlan", "no", "hostname", "do", "exit", "end", "help"}
		case ModeConfigIf:
			return []string{"shutdown", "no", "switchport", "speed", "flowcontrol", "exit", "end", "help"}
		case ModeConfigVlan:
			return []string{"name", "shutdown", "no", "exit", "end", "help"}
		}
		return nil
	}
	first := lc(precedingFields[0])
	switch {
	case (first == "show" || first == "sh") && len(precedingFields) == 1:
		return []string{"version", "vlan", "interfaces", "interface", "running-config"}
	case (first == "configure" || first == "conf") && len(precedingFields) == 1:
		return []string{"terminal"}
	case first == "switchport" && len(precedingFields) == 1:
		return []string{"mode", "access", "trunk"}
	case first == "switchport" && len(precedingFields) == 2 && lc(precedingFields[1]) == "mode":
		return []string{"access", "trunk"}
	case first == "no" && len(precedingFields) == 1 && mode == ModeConfig:
		return []string{"vlan"}
	case first == "no" && len(precedingFields) == 1 && mode == ModeConfigIf:
		return []string{"shutdown", "switchport"}
	case first == "speed" && len(precedingFields) == 1:
		return []string{"auto", "10", "100", "1000"}
	case first == "flowcontrol" && len(precedingFields) == 1:
		return []string{"on", "off"}
	case first == "do" && len(precedingFields) == 1:
		return []string{"show"}
	case first == "clear" && len(precedingFields) == 1:
		return []string{"counters"}
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
	if si, err := sw.fetchSysInfo(); err == nil && si.Desc != "" {
		hostname = si.Desc
	}

	cli := &CLI{sw: sw, mode: ModeUser, hostname: hostname}

	var histFile string
	if home, err := os.UserHomeDir(); err == nil {
		histFile = filepath.Join(home, ".tpios_history")
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:       cli.prompt() + " ",
		HistoryFile:  histFile,
		AutoComplete: &cliCompleter{cli: cli},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "readline init failed:", err)
		os.Exit(1)
	}
	defer rl.Close()
	cli.out = bufio.NewWriter(rl.Stdout())

	fmt.Fprintln(rl.Stdout())
	fmt.Fprintln(rl.Stdout(), "User Access Verification")
	fmt.Fprintln(rl.Stdout())
	fmt.Fprintf(rl.Stdout(), "%s con0 is now available\n", hostname)
	fmt.Fprintln(rl.Stdout(), "Press RETURN to get started.")
	fmt.Fprintln(rl.Stdout())

	defer sw.logout()

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
		if cli.handleLine(line) {
			break
		}
	}
	fmt.Fprintln(rl.Stdout(), "Connection closed.")
}
