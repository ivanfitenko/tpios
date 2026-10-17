# Concerns / gotchas for anyone using or extending tpios

tpios drives the TP-Link EasySmart web UI (`*.cgi`/`*.htm` endpoints) the way a
browser does - there is no official API, no stability guarantee, and the
reverse-engineering below was done against one device
(TL-SG1024DE, hardware 7.0, firmware `1.0.0 Build 20230616 Rel.34205`).
Other models/firmware in the EasySmart line (TL-SG108E, TL-SG1016DE, ...)
likely share most of this but have not been verified.

## The device's HTTP server is fragile under load

During development, firing off ~7 overlapping `curl`/raw-socket login
attempts in quick succession left the device's web server completely
unresponsive - not just `/logon.cgi`, but plain `GET /` too - while ICMP
ping kept working fine. The browser UI was also affected; it took a power
cycle to recover.

This strongly suggests a single-threaded (or very small worker pool) HTTP
server with no graceful handling of a backlog of stalled/abandoned
connections. **Never issue concurrent or rapid-retry requests against this
device.** tpios's design (one blocking HTTP call at a time, REPL-paced by a
human typing) stays well inside what we've seen it handle, but any rewrite
or added concurrency should preserve that: strictly sequential requests,
no background retries in a tight loop, and a real pause (not an
immediate re-request) if a call times out.

If the UI ever becomes totally unresponsive (ICMP still OK, HTTP dead),
the only known fix we found was a physical power cycle.

## The web server takes longer to come up than ping/ARP after a power cycle

After a power cycle, the switch answers ICMP ping and ARP well before its
web server is actually listening on port 80. A `tpios`/`curl` connection
attempt in that window fails at the TCP layer - on macOS this surfaces as
`dial tcp ...: connect: no route to host`, which reads like a network
problem but isn't one; it's specifically that nothing is listening on
port 80 yet (a listening-but-rejecting port would normally show
"connection refused" instead). Ping succeeding is not a reliable signal
that the switch is ready - if a connection attempt fails right after a
power cycle, wait another 30-60s and retry rather than treating it as a
network/config problem.

## A one-shot TCP connect can fail transiently with "no route to host" even when the switch is fine

Observed live: `tpios` failed with
`dial tcp 192.168.1.100:80: connect: no route to host`, while `ping` and a
plain `curl GET /` run immediately afterward both succeeded instantly. We
checked for the obvious suspects (McAfee or any other AV/firewall
software, macOS Application Firewall, registered network extensions) and
found none active on the test machine - the firewall was off and nothing
was installed. The likely explanation is a brief client-side ARP-cache
hiccup on the Mac at the exact moment of the connect() call (possibly
nudged along by a browser tab also sitting on the switch's UI,
contending for its very limited connection handling - see the first
concern above), which clears itself within a second or two.

This is a different failure signature from the device-wedged case: here
the error happens immediately at the dial stage (`net.OpError.Op ==
"dial"`), not after the client's multi-second timeout waiting for a
response. tpios distinguishes the two deliberately - `login()` and
`rawGet()` now retry up to 3 times with a 1.5s pause **only** when the
error is a dial-stage failure. A hang after the connection is established
(the device itself not responding) is left alone and surfaced to the
user, since auto-retrying that case would mean piling more connections
onto a device that may already be struggling (see above).

## macOS "Local Network" permission can silently block tpios in an existing Terminal window

Confirmed live: `tpios` failed consistently with
`dial tcp 192.168.1.100:80: connect: no route to host` when run from one
specific, long-running Terminal window - while `ping` and `curl` in that
*same* window, moments apart, worked fine. The code's own retry logic
(see above) didn't help because the failure wasn't transient for that
window; it was consistent for as long as that window stayed open. Closing
browsers, ruling out AV/firewall software, and checking the switch's own
health all came up clean - the asymmetry was "this Terminal window" vs.
"everything else" (another tool's shell, curl, ping, a brand new Terminal
window), which pointed at a per-process macOS permission rather than
anything about the network or the device.

The fix was simply opening a **new** Terminal window and running `tpios`
there - it worked immediately. The working theory: macOS's "Local
Network" privacy permission (System Settings -> Privacy & Security ->
Local Network) is granted per-app/per-process, is enforced inconsistently
for unsigned CLI binaries (sometimes no visible prompt at all, just a
silent block), and the grant/denial decision for a given process can get
"stuck" for the lifetime of that process/shell - especially plausible if
the permission state changed, or the binary was rebuilt with a different
signature, after that Terminal window was already open. Apple's `curl`
and `ping` are pre-trusted system binaries and aren't subject to the same
check, which is why they kept working the whole time and gave no hint
that anything was wrong with the network or the device.

**If `tpios` (or any freshly-built Go binary) fails this way - TCP
`dial`-stage failure, while `ping`/`curl` succeed in the same window -
close that terminal and open a new one before looking anywhere else.**
A full reboot is the heavier-handed version of the same fix if a fresh
terminal alone doesn't clear it.

## `logon.cgi` has undocumented requirements

A POST to `/logon.cgi` with just `username` and `password` hung forever -
no HTTP response at all, not even an error page - no matter how long we
waited (tested up to 60s) or how browser-like the headers were made.

The actual working request (confirmed against the real device) needs:
- A third form field: `logon=Login` (the submit button's name/value in the
  real form)
- Header `Referer: http://<ip>/Logout.htm` (not `/`, as you might expect)

Omit either and the request doesn't error - it just never responds. This
cost significant debugging time and very likely explains odd "my script
can't log in" reports from anyone replicating this.

On success the server sets `Set-Cookie: H_P_SSID=...;Max-Age=600` - the
session is good for **10 minutes**. tpios re-logs in proactively after
540s, and falls back to detecting a login-page response body
(`name="username"`) and re-authenticating transparently on any call.

## Some config writes are much slower than page reads than you'd expect

Plain `GET`s of `*.htm` status pages return in well under a second.
But certain "apply" writes - toggling 802.1Q on/off via `qvlanSet.cgi`
and setting the device description via `system_name_set.cgi` - have been
observed taking longer than 8 seconds to respond, apparently because
they commit to flash/NVRAM. **The write still succeeds even though the
client-side request appears to hang** - we verified this by timing out
client-side, then independently re-querying the device and finding the
change had, in fact, applied.

tpios uses a 20s client timeout for this reason. A shorter timeout will
produce false "it failed" errors for changes that actually went through -
don't treat a timeout on these specific endpoints as proof of failure
without re-checking device state.

## VLAN creation silently no-ops with zero port members

If you POST a new VLAN to `qvlanSet.cgi` with every `selType_N=2` ("not a
member") - i.e. create a VLAN with no ports assigned - the device responds
`200 OK` with `tip: "Operation successful."` and then **does not create
the VLAN at all**. A follow-up `GET Vlan8021QRpm.htm` shows no trace of it.

There is no error, no distinguishing response - it looks identical to a
genuine success. The only way we found to confirm this was to submit the
exact same request but with one port set to tagged or untagged, which did
persist.

Implication: this hardware cannot represent an "empty" VLAN the way real
Cisco IOS can (`vlan 10` with zero assigned ports is a completely normal,
valid state on a 2960). tpios works around this by keeping any name set
before a port is assigned in memory (`pendingNames`) and only actually
writing the VLAN to the device once `switchport access`/`switchport trunk`
gives it a real member. Anyone building on top of this should never
assume a `qvlanSet.cgi` 200 response means the VLAN exists - always
re-fetch and check.

## The device does not enforce untagged-VLAN exclusivity

On real 802.1Q hardware, a port has exactly one PVID/untagged VLAN. This
device will happily let a port be an untagged member of *multiple* VLANs
simultaneously if you write to each VLAN independently - it does not
clean up the others for you. We reproduced this directly: creating a new
VLAN with a port as untagged member left that port untagged in the old
VLAN too, until we explicitly cleared it.

tpios's `switchport access vlan <id>` therefore always walks every other
known VLAN and clears the port's bit from their untagged masks as a
separate explicit step. Any direct `qvlanSet.cgi` caller that skips this
will end up with overlapping/ambiguous untagged membership that the web UI
itself doesn't warn about.

## No read API for per-port PVID

There's a write endpoint (`vlanPvidSet.cgi`) but no page that reports a
port's current PVID directly. tpios derives the "Vlan" column in
`show interfaces status` / `show running-config` by scanning which VLAN's
*untagged* bitmask contains the port - this is a reasonable proxy (PVID
and untagged membership are set together by `switchport access`) but it
is an inference, not a direct read, and could drift out of sync if
something else (the web UI, a factory reset, manual `vlanPvidSet.cgi`
calls) changes PVID without touching untagged membership to match.

## `show interface(s)` detail: what's real, what's a universal constant, what's omitted

Real IOS's `show interfaces` is famously dense - hardware address, MTU,
bandwidth, encapsulation, load/reliability, flow control, and a long tail
of packet/error/queue counters. This device cannot back most of that, so
the detailed per-port view (`show interface <n>` and bare `show
interfaces`) deliberately mixes three different kinds of line:

- **Real device data**: admin/line state, configured/actual speed and
  duplex, flow control, and - once `PortStatisticsRpm.htm` was explored -
  real per-port packet counters (see below).
- **Universal protocol constants**: MTU 1500, `Encapsulation ARPA`,
  `Keepalive not supported`, `BW 1000000 Kbit/sec` (this hardware's ports
  are all gigabit-capable), the idle `reliability 255/255, txload 1/255,
  rxload 1/255` baseline. These are true by spec for essentially any
  Ethernet switchport, not a guess about this specific device, so they're
  shown even though they aren't read from it.
- **Omitted, not fabricated**: queue depths, byte counts, broadcast/
  multicast breakdowns, CRC/runt/giant/collision counters, last-input
  timestamps - anything that would require inventing a device-specific
  number with no way to verify it. Showing a confident `0` for something
  we genuinely don't know is worse than not showing it.

Two specific simplifications worth knowing if you touch this code:
- **Hardware address is the device's one system-wide MAC, repeated for
  every port.** This switch exposes no per-port MAC (unlike real Cisco's
  per-interface "bia" addresses) - there's only one MAC in
  `SystemInfoRpm.htm`, and it's shown for all 24 interfaces.
- **Flow control has no separate input/output setting on this device** -
  `fc_cfg`/`fc_act` are one combined value, so both the "input
  flow-control is X" and "output flow-control is X" lines always show the
  same thing, unlike real Cisco which can show them independently.

## Real per-port traffic counters, via `PortStatisticsRpm.htm`

`PortStatisticsRpm.htm` exposes a flat `pkts` array, 4 ints per port in a
fixed order: `[TxGoodPkt, TxBadPkt, RxGoodPkt, RxBadPkt]`. No byte counts,
no finer error taxonomy (no CRC/runt/giant/collision breakdown - just one
lumped "bad" count per direction). `show interface`/`show interfaces` use
this for real `"N packets input, N received in error"` /
`"N packets output, N sent in error"` lines.

The page also has a `Clear` button -> `port_statistics_set.cgi?clear=Clear`,
mapped to `clear counters` in tpios. Verified live: a port with 10484
packets in / 4948 out dropped to 0 immediately after `clear counters`,
then continued accumulating real traffic from that point. The device only
supports clearing **all** ports at once - there's no per-port clear, so
`clear counters <interface>` isn't supported (tpios rejects it with a
message rather than silently clearing everything when you asked for one
port).

## LAG (link aggregation) parsing is unverified against real data

`show running-config` reads `PortTrunkRpm.htm`'s `portStr_g1`..`portStr_g8`
arrays to list any configured LAG groups. The test unit has no LAG
configured, so every one of those arrays is all zeros - the parsing (any
nonzero entry means "this port is a member of this group") has never been
exercised against a real non-empty group. It's a reasonable reading of the
field names but unconfirmed; treat LAG output with suspicion until someone
verifies it on a switch with an actual LAG configured.

## QoS / bandwidth / storm-control settings are not read

The menu also exposes `QosBasicRpm`, `QosBandWidthControlRpm`, and
`QosStormControlRpm`. These weren't added to `show running-config` - the
storm-control page in particular has a `scInfo` array with 3 values per
port whose exact encoding (enabled flag? rate unit? rate value? which
order?) wasn't reverse-engineered, and the test device has everything at
default (all zeros), so there's no live non-default data to check a guess
against. Skipped rather than shipping unverified parsing.

## "loop-detection" and "ip igmp snooping" in running-config aren't real IOS syntax for this exact feature

`show running-config` reflects this switch's "Loop Prevention" toggle as
`loop-detection` and its IGMP Snooping toggle as `ip igmp snooping`. The
IGMP line happens to match real Cisco syntax; the loop-prevention one is
invented for plausibility - there's no single universal IOS command for
what this specific TP-Link feature does (auto-disable a port when a loop
is detected). Both are read-only in tpios (no CLI verb sets them yet).

## Other known limitations / deliberate non-features

- **`reload` is a stub.** It prints the Cisco-style confirmation prompt
  text but refuses to actually reboot the device. Given how fragile the
  HTTP server has shown itself to be, wiring this to a real reboot
  endpoint felt like the wrong default; if someone wants it, it should be
  opt-in and loudly confirmed.
- **No `show mac address-table`.** We didn't find a page exposing the
  dynamic MAC table during this investigation; the command just reports
  "not supported on this platform."
- **No `interface range` support.** Each port must be configured one at a
  time.
- **`do` in config mode only supports `do show ...`**, not arbitrary
  passthrough.
- **VLAN names are capped at 10 characters** by the device's own web form
  (`maxlength=10` on the VLAN name input) - longer names will likely be
  truncated or rejected server-side; tpios doesn't currently validate this
  client-side.
- **Everything is plaintext HTTP, no CSRF token, no TLS.** The login form
  POSTs `username`/`password` in the clear and there is nothing like a
  per-session token protecting state-changing GET requests
  (`port_setting.cgi`, `qvlanSet.cgi`, etc. are all plain GETs with query
  params - a CSRF-able pattern if this device is ever exposed beyond a
  trusted LAN). This is a property of the device, not of tpios, but
  anyone deploying this should keep the switch's management interface off
  anything but a trusted, isolated management network.

## Verified-safe test methodology, if you extend this

Everything above was confirmed by testing live against a real switch, one
sequential request at a time, always picking an unused/link-down port for
destructive tests (port 2 on our test unit), and always re-verifying
(`show vlan`/`show interfaces status`) and reverting to the original
state afterward rather than trusting a 200 response. Given the fragility
documented above, that discipline matters more than it would for a normal
REST API - trust observed device state over HTTP status codes.
