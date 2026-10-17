#!/bin/sh
# Run on the router after any firmware update or reboot.
# Vendor updates can silently reset these settings.

echo "flow_offloading (expect 0):  $(uci -q get firewall.@defaults[0].flow_offloading)"
echo "upnp enabled (expect 0):     $(uci -q get upnpd.config.enabled)"
echo "dns localservice (expect 1): $(uci -q get dhcp.@dnsmasq[0].localservice)"
echo "syslog target (expect IDS):  $(uci -q get system.@system[0].log_ip)"
uci show sqm 2>/dev/null | grep -E "download|upload"
for f in /usr/share/nftables.d/table-post/30-quarantine.nft /usr/bin/quarantine-cmd; do
  [ -e "$f" ] && echo "present: $f" || echo "MISSING: $f"
done
nft list set inet fw4 quarantine >/dev/null 2>&1 && echo "quarantine set: loaded" || echo "quarantine set: MISSING"
