# Passive network inventory protocol 1. Only selected fields leave this helper.
import ipaddress, json, os, platform, re, shutil, subprocess, sys, tempfile

json.load(sys.stdin)
result = {"protocol": 1, "os": platform.system(), "arch": platform.machine(), "capabilities": [], "interfaces": [], "routes": [], "policy_rules": [], "resolvers": [], "processes": [], "tailscale": {"present": False, "running": False, "exit_node": False, "ips": []}}

def run(args, label, timeout=2):
    exe = shutil.which(args[0])
    if not exe:
        result["capabilities"].append({"name": label, "available": False, "detail": "command unavailable"})
        return None
    try:
        with tempfile.TemporaryFile() as output:
            env = dict(os.environ)
            env["LC_ALL"] = "C"
            child = subprocess.run([exe] + args[1:], stdout=output, stderr=subprocess.DEVNULL, timeout=timeout, env=env)
            output.seek(0)
            data = output.read(2 * 1024 * 1024 + 1)
        ok = child.returncode == 0 and len(data) <= 2 * 1024 * 1024
        result["capabilities"].append({"name": label, "available": ok, "detail": "" if ok else "command denied, failed or exceeded its output limit"})
        return data.decode("utf-8", "replace") if ok else None
    except (OSError, subprocess.TimeoutExpired):
        result["capabilities"].append({"name": label, "available": False, "detail": "command failed or timed out"})
        return None

def decode(value):
    try:
        return json.loads(value) if value else None
    except (ValueError, TypeError):
        return None

def prefix(value, family=4):
    if value == "default":
        return "0.0.0.0/0" if family == 4 else "::/0"
    if "%" in value:
        address, zone = value.split("%", 1)
        value = address + ("/" + zone.split("/", 1)[1] if "/" in zone else "")
    try:
        if ":" not in value:
            bits = value.split("/", 1)
            parts = bits[0].split(".")
            if len(parts) < 4:
                value = ".".join(parts + ["0"] * (4 - len(parts))) + "/" + (bits[1] if len(bits) > 1 else str(len(parts) * 8))
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None

try:
    address = os.environ.get("SSH_CONNECTION", "").split()[0]
    result["management_address"] = str(ipaddress.ip_address(address))
except (ValueError, IndexError):
    pass

if platform.system() == "Linux":
    rows = decode(run(["ip", "-j", "-d", "address", "show"], "interfaces"))
    for row in (rows or [])[:128]:
        result["interfaces"].append({"name": row.get("ifname", ""), "state": row.get("operstate", ""), "kind": row.get("linkinfo", {}).get("info_kind", row.get("link_type", "")), "addresses": [str(a.get("local", "")) for a in row.get("addr_info", [])[:16]]})
    for family in (4, 6):
        rows = decode(run(["ip", "-j", "-" + str(family), "route", "show", "table", "all"], "routes-ipv" + str(family)))
        for row in (rows or [])[:2048]:
            destination = prefix(str(row.get("dst", "default")), family)
            if destination:
                result["routes"].append({"destination": destination, "gateway": str(row.get("gateway", "")), "interface": str(row.get("dev", "")), "table": str(row.get("table", "main"))})
        rows = decode(run(["ip", "-j", "-" + str(family), "rule", "show"], "policy-ipv" + str(family)))
        for row in (rows or [])[:256]:
            safe = {k: row[k] for k in ("priority", "src", "dst", "table", "fwmark", "iif", "oif", "action") if k in row}
            result["policy_rules"].append(json.dumps(safe, sort_keys=True))
    dns = run(["resolvectl", "dns"], "scoped-dns") or ""
    domains = run(["resolvectl", "domain"], "scoped-dns-domains") or ""
    resolvers = {}
    for text, field in ((dns, "servers"), (domains, "domains")):
        for line in text.splitlines():
            match = re.match(r"(?:Link\s+\d+\s+\(([^)]+)\)|Global):\s*(.*)$", line)
            if match:
                name = match.group(1) or "global"
                row = resolvers.setdefault(name, {"interface": name, "servers": [], "domains": []})
                row[field] = match.group(2).split()[:64]
    result["resolvers"] = list(resolvers.values())
    if not result["resolvers"]:
        try:
            with open("/etc/resolv.conf") as source:
                text = source.read(16384)
            servers = re.findall(r"(?m)^\s*nameserver\s+(\S+)", text)
            domains = re.findall(r"(?m)^\s*(?:search|domain)\s+(.*)$", text)
            result["resolvers"].append({"interface": "resolv.conf (not scoped)", "servers": servers[:16], "domains": " ".join(domains).split()[:32]})
        except OSError:
            pass
elif platform.system() == "Darwin":
    text = run(["ifconfig", "-a"], "interfaces") or ""
    current = None
    for line in text.splitlines():
        match = re.match(r"^(\S+): flags=.*?<([^>]*)>", line)
        if match:
            name, flags = match.groups()
            current = {"name": name, "state": "UP" if "UP" in flags.split(",") else "DOWN", "kind": "tunnel" if name.startswith(("utun", "tun", "tap", "ppp")) else "interface", "addresses": []}
            result["interfaces"].append(current)
        elif current is not None:
            match = re.match(r"\s*inet6?\s+(\S+)", line)
            if match:
                current["addresses"].append(match.group(1))
    names = set(row["name"] for row in result["interfaces"])
    for family, number in (("inet", 4), ("inet6", 6)):
        text = run(["netstat", "-rn", "-f", family], "routes-" + family) or ""
        for line in text.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            destination = prefix(cols[0], number)
            interface = next((c for c in cols[2:] if c in names), "")
            if destination and interface:
                gateway = cols[1] if not cols[1].startswith("link#") else ""
                result["routes"].append({"destination": destination, "gateway": gateway, "interface": interface, "table": "main", "scoped": "I" in cols[2]})
    text = run(["scutil", "--dns"], "scoped-dns") or ""
    current = None
    for line in text.splitlines():
        if re.match(r"resolver #\d+", line):
            current = {"interface": "", "servers": [], "domains": []}
            result["resolvers"].append(current)
        elif current is not None:
            server = re.match(r"\s*nameserver\[\d+\]\s*:\s*(\S+)", line)
            domain = re.match(r"\s*(?:domain|search domain\[\d+\])\s*:\s*(\S+)", line)
            interface = re.match(r"\s*if_index\s*:\s*\d+\s*\(([^)]+)\)", line)
            if server:
                current["servers"].append(server.group(1))
            if domain:
                current["domains"].append(domain.group(1))
            if interface:
                current["interface"] = interface.group(1)
else:
    result["capabilities"].append({"name": "platform", "available": False, "detail": "supported network inventory platforms are Darwin and Linux"})

if shutil.which("tailscale"):
    result["tailscale"]["present"] = True
    status = decode(run(["tailscale", "status", "--json"], "tailscale-status", 3))
    if isinstance(status, dict):
        result["tailscale"].update({"running": status.get("BackendState") == "Running", "exit_node": bool((status.get("ExitNodeStatus") or {}).get("ID")), "suffix": str((status.get("CurrentTailnet") or {}).get("MagicDNSSuffix", "")), "ips": status.get("TailscaleIPs", [])[:8]})
    prefs = decode(run(["tailscale", "debug", "prefs"], "tailscale-preferences", 3))
    if isinstance(prefs, dict):
        result["tailscale"]["exit_node"] = result["tailscale"]["exit_node"] or bool(prefs.get("ExitNodeID")) or prefs.get("ExitNodeIP", "") not in ("", "0.0.0.0", "::", None)

text = run(["ps", "-axo", "comm="], "vpn-processes") or ""
matches = ("mihomo", "clash", "tailscaled", "safeconnect", "openvpn", "openconnect", "vpnagent", "forti", "globalprotect", "charon", "wireguard")
for line in text.splitlines():
    name = os.path.basename(line.strip())
    if any(word in name.lower() for word in matches) and name not in result["processes"]:
        result["processes"].append(name[:128])

json.dump(result, sys.stdout, ensure_ascii=True, separators=(",", ":"))
