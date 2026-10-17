# Home Network Hardening: Segmented Lab with IDS-Driven Quarantine

A segmented home network built on a GL.iNet Flint 3 (OpenWrt-based) router, with a Raspberry Pi 5 running Suricata in Docker. Suricata alerts feed a notifier that can quarantine a compromised device on the router through a tightly restricted SSH key.

This repo documents the design, the scripts, and an outage that happened along the way, including the mistakes. Sensitive details (public IP, MAC addresses, SSIDs, usernames, keys, alert topics) have been removed.

## Architecture

| Segment | VLAN | Subnet | Purpose | Internet |
|---|---|---|---|---|
| Main | 1 | 192.168.8.0/24 | Trusted clients | Yes |
| Guest | 9 | 192.168.9.0/24 | Visitors, client isolation | Yes |
| IoT | 20 | 192.168.10.0/24 | Smart devices, client isolation | Yes |
| Gaming | 10 | 192.168.20.0/24 | Single wired PC | Yes |
| Lab | 50 | 192.168.50.0/24 | Raspberry Pi (Suricata, EveBox, reverse proxy) | Yes |
| Quarantine | 99 | 192.168.99.0/24 | Holding cell, DHCP only | **No** |
| WireGuard | n/a | 10.1.0.0/24 | Remote access | Via router |

- Default policy is deny. Each zone gets only DHCP and DNS from the router.
- Cross-zone access is limited to single-host, single-port rules (PC to Pi on SSH and the proxy ports; phone tunnel to Pi on SSH).
- The router is the only DNS server for every segment, forwarding to AdGuard Home.

## Detection and response pipeline

```
Suricata (Pi) -> eve.json -> ids_quarantine.py -> ntfy push to phone
                                   |
                                   +-> ssh (forced command) -> router quarantine-cmd
                                                                 -> nftables set (2h timeout)
```

**Two layers of quarantine:**

1. **IP quarantine set** (`router/30-quarantine.nft`): fast and automatable. Drops all forwarded and router-bound traffic to and from an address, expiring after 2 hours.
2. **Quarantine VLAN 99**: manual holding cell for longer investigations. No forwardings, DROP policy, DHCP only, plus a hidden Wi-Fi network that stays disabled until needed.

## Security design decisions

- **The Pi never gets root on the router.** Its key is bound to a forced command (`router/quarantine-cmd`) that accepts only `add <ip>`, `del <ip>`, and `list`. Validation lives on the router, so a compromised Pi cannot bypass it:
  - home subnets only
  - gateways, the Pi, and the gaming PC are protected
  - at most 5 devices quarantined at once
  - every request logged
- **Dry-run first.** The notifier reports "would quarantine X" for a week before it is allowed to act.
- **High-confidence triggers only.** Severity 1 alerts in trojan, C2, privilege-gain, and exploit-kit categories. Informational alerts never cause action.
- **No shell strings.** SSH is invoked with an argument list, removing command injection risk from alert fields.
- **Off-box logging.** Router syslog is shipped to the Pi so a crash leaves evidence.

## Incident summary (October 15)

While following AI-generated instructions to add router-side packet mirroring, the whole network went down, including Wi-Fi.

- **Likely cause:** a hung kernel module install (`kmod-ipt-tee`) on the vendor kernel. Unprovable, because router logs lived only in RAM and were lost on power cycle.
- **Confirmed secondary cause:** a DHCP option pointed one VLAN's DNS at the Pi, which the firewall blocked.
- **Also found:**
  - The previous quarantine was never persistent (fw4 ignores `/etc/firewall.user`).
  - The Pi held a passwordless root key to the router.
  - Suricata had been silently down for 27 hours after a log rotation permission failure and a reboot.

Full write-up: [docs/incident-2026-10-15.md](docs/incident-2026-10-15.md)

**Rules adopted afterward:**

1. Back up before every change.
2. Make one change, then verify it.
3. Run `fw4 check` before every firewall restart.
4. No kernel module installs on the router.
5. Automation gets scoped keys only.
6. Ship logs off-box.

## Repo layout

```
router/30-quarantine.nft     nftables set and chains, auto-loaded by fw4
router/quarantine-cmd        forced-command gatekeeper for the Pi's key
router/post-update-check.sh  verifies settings that firmware updates can reset
pi/ids_quarantine.py         Suricata alert notifier with guarded quarantine
pi/ids-quarantine.service    systemd unit (dry-run by default)
pi/logrotate-suricata        copytruncate rotation, no reopen signal needed
pi/rsyslog-router.conf       receives router syslog, accepts only the router
docs/incident-2026-10-15.md  postmortem
```

## Known limitations

- Suricata currently sees only the Pi's own traffic. Network-wide visibility needs a managed switch with a mirror port, which still won't see Wi-Fi traffic. Full coverage needs a dedicated firewall such as OPNsense.
- The IP quarantine cannot stop traffic between two devices on the same switch or Wi-Fi segment, because it never crosses the router.

## Status

- [x] Segmentation, quarantine set, restricted key, alerting (dry-run), router hardening, quarantine VLAN
- [ ] Port mirroring with a managed switch
- [ ] Switch the notifier from dry-run to live
