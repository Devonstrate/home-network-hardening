#!/usr/bin/env python3
"""Suricata alert notifier with guarded quarantine. Dry-run unless DRY_RUN=0.

Config:
  EVE_LOG        path to Suricata eve.json (env, default below)
  DRY_RUN        "0" to act, anything else to only notify
  ~/.config/ids-alert/ntfy_topic   private ntfy topic (chmod 600, not in git)
  ~/.ssh/quarantine_router         forced-command key for the router
"""
import ipaddress, json, os, subprocess, sys, time, urllib.request
from collections import deque

EVE_LOG = os.environ.get("EVE_LOG", os.path.expanduser("~/services/suricata/logs/eve.json"))
DRY_RUN = os.environ.get("DRY_RUN", "1") != "0"
TOPIC_FILE = os.path.expanduser("~/.config/ids-alert/ntfy_topic")
SSH_KEY = os.path.expanduser("~/.ssh/quarantine_router")
ROUTER = "root@192.168.50.1"

HOME_NETS = [ipaddress.ip_network(n) for n in (
    "192.168.8.0/24", "192.168.9.0/24", "192.168.10.0/24",
    "192.168.20.0/24", "192.168.50.0/24")]
PROTECTED = {"192.168.8.1", "192.168.9.1", "192.168.10.1", "192.168.20.1",
             "192.168.50.1", "192.168.50.115", "192.168.20.244"}
TRIGGER_CATEGORIES = {
    "A Network Trojan was detected",
    "Malware Command and Control Activity Detected",
    "Attempted Administrator Privilege Gain",
    "Successful Administrator Privilege Gain",
    "Exploit Kit Activity Detected",
    "Targeted Malicious Activity was Detected",
}
MAX_ACTIONS_PER_HOUR = 3
DEDUP_SECONDS = 600

recent_actions = deque()
last_seen = {}


def log(msg):
    print(msg, flush=True)


def is_home(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in HOME_NETS)


def pick_target(src, dst):
    if is_home(src):
        return src
    if is_home(dst):
        return dst
    return None


def rate_ok():
    now = time.time()
    while recent_actions and now - recent_actions[0] > 3600:
        recent_actions.popleft()
    return len(recent_actions) < MAX_ACTIONS_PER_HOUR


def router(*args):
    cmd = ["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=5", ROUTER, *args]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def notify(title, body, priority="default"):
    try:
        with open(TOPIC_FILE) as f:
            topic = f.read().strip()
        req = urllib.request.Request(
            "https://ntfy.sh/" + topic, data=body.encode("utf-8"),
            headers={"Title": title.encode("ascii", "replace").decode(),
                     "Priority": priority, "Tags": "shield"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        log("notify failed: %s" % e)


def handle(ev):
    a = ev.get("alert", {})
    if a.get("severity") != 1:
        return
    sig = a.get("signature", "unknown")
    cat = a.get("category", "")
    src, dst = ev.get("src_ip", ""), ev.get("dest_ip", "")
    now = time.time()
    key = (a.get("signature_id"), src, dst)
    if now - last_seen.get(key, 0) < DEDUP_SECONDS:
        return
    last_seen[key] = now

    target = pick_target(src, dst)
    priority = "high"
    if cat not in TRIGGER_CATEGORIES:
        status, priority = "Alert only (category is not a trigger)", "default"
    elif not target:
        status = "Alert only (no home-network device involved)"
    elif target in PROTECTED:
        status = "Alert only (%s is protected)" % target
    elif not rate_ok():
        status = "NOT quarantined (%s): rate limit reached" % target
    elif DRY_RUN:
        recent_actions.append(now)
        status = "DRY RUN: would quarantine %s for 2h" % target
    else:
        ok, out = router("add", target)
        if ok:
            recent_actions.append(now)
            status, priority = "QUARANTINED %s for 2h" % target, "urgent"
        else:
            status = "Quarantine FAILED for %s: %s" % (target, out)

    body = "%s\n%s -> %s\nCategory: %s\nStatus: %s" % (sig, src, dst, cat, status)
    if target and status.startswith(("QUARANTINED", "DRY RUN")):
        body += "\nRelease: ssh -i ~/.ssh/quarantine_router %s del %s" % (ROUTER, target)
    log(body.replace("\n", " | "))
    notify("IDS Sev 1: " + sig[:60], body, priority)


def follow(path):
    while not os.path.exists(path):
        time.sleep(2)
    f = open(path)
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    buf = ""
    while True:
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith("\n"):
                yield buf
                buf = ""
            continue
        time.sleep(0.5)
        try:
            st = os.stat(path)
            if st.st_ino != inode or st.st_size < f.tell():
                f.close()
                f = open(path)
                inode = os.fstat(f.fileno()).st_ino
                buf = ""
        except FileNotFoundError:
            pass


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else EVE_LOG
    log("started: dry_run=%s log=%s" % (DRY_RUN, path))
    for line in follow(path):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("event_type") == "alert":
            try:
                handle(ev)
            except Exception as e:
                log("error handling alert: %s" % e)


if __name__ == "__main__":
    main()
