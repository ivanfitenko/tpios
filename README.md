# tpios

Built purely out of love and nostalgia for the `enable` /
`configure terminal` / `show interfaces status` muscle memory that an
entire generation learned on then-world-leding gear, and that the rest of the
networking world unjustly left behind.

There is no API on these switches. tpios drives the same `*.cgi`/`*.htm`
endpoints the device's own web UI uses.

## Persistent config

tpios found an undocumented property of this switch's firmware that lets
it save your configuration the "classic" way - inside the device itself,
exactly where a real switch's startup-config belongs. On first run, you
can opt out and keep it in a local file instead, following the XDG Base
Directory standard.

## Build

```
make build
```

(`make` / `make all` do the same thing.) Requires Go 1.21+; fetches one
dependency (`github.com/chzyer/readline`, MIT - see
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)) the first time.

## Use

```
./tpios <switch-ip>
```

You'll be prompted for a username and password every run - never cached,
never taken as a command-line argument. For a switch with fewer than 24
ports:

```
./tpios -ports 16 <switch-ip>
```

Now it can be controlled in a way you are used to:

```
Switch> enable
Switch# show interfaces status
Switch# configure terminal
Switch(config)# interface gi0/3
Switch(config-if)# shutdown
```

Tab completes commands, a line ending in `?` lists what can come next,
and command history persists in `~/.tpios_history`.

## License

BSD-3-Clause - see [`LICENSE`](LICENSE).
