# lazyclash host evidence protocol 1. Fixed code; request data arrives on stdin.
import datetime, ipaddress, json, os, platform, queue, re, shutil, socket, subprocess, sys, threading, time, urllib.parse

request = json.load(sys.stdin)
host, port, observe = request["host"], int(request["port"]), bool(request["observe_only"])
result = {"protocol": 1, "scope": "host", "system": platform.system(), "capabilities": [], "environment": {}, "dns": {"source": "host native resolver", "addresses": []}, "routes": [], "requests": []}

def capability(name, available, detail=""):
    result["capabilities"].append({"name": name, "available": available, "detail": detail})

def command(args, timeout=2):
    try:
        completed = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        if completed.returncode != 0 or len(completed.stdout) > 65536:
            return None
        return completed.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return None

def safe_proxy(value):
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlsplit(value if "://" in value else "http://" + value)
        if not parsed.hostname or parsed.scheme not in ("http", "https", "socks5", "socks5h", "socks4", "socks4a"):
            return "<set; unrecognized proxy>"
        hostname = "[" + parsed.hostname + "]" if ":" in parsed.hostname else parsed.hostname
        return parsed.scheme + "://" + hostname + (":" + str(parsed.port) if parsed.port else "")
    except (ValueError, TypeError):
        return "<set; invalid proxy>"

def excluded(value):
    hostname = host.lower().rstrip(".")
    for item in value.split(","):
        item = item.strip().lower()
        if item == "*":
            return True
        if not item:
            continue
        try:
            if "/" in item and ipaddress.ip_address(hostname.strip("[]")) in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            pass
        item = item.lstrip(".").rstrip(".")
        if hostname == item or hostname.endswith("." + item):
            return True
    return False

variables = []
for key in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
    if os.environ.get(key):
        variables.append({"name": key, "endpoint": safe_proxy(os.environ[key])})
no_proxy = os.environ.get("no_proxy", os.environ.get("NO_PROXY", ""))
scheme = urllib.parse.urlsplit(request["url"]).scheme
selected = os.environ.get(scheme + "_proxy", "")
if not selected and scheme != "http":
    selected = os.environ.get(scheme.upper() + "_PROXY", "")
selected = selected or os.environ.get("all_proxy", os.environ.get("ALL_PROXY", ""))
result["environment"] = {"proxies": variables, "no_proxy_set": bool(no_proxy), "no_proxy_matches": excluded(no_proxy), "selected_proxy": safe_proxy(selected), "interpretation": "Observed process environment; curl-compatible no_proxy interpretation is not proof of actual proxy use. HTTP_PROXY uppercase is ignored by curl."}

os_proxy = {}
if request.get("request_only"):
    pass
elif platform.system() == "Darwin" and shutil.which("scutil"):
    text = command([shutil.which("scutil"), "--proxy"])
    if text is not None:
        for line in text.splitlines():
            match = re.match(r"\s*(HTTPEnable|HTTPProxy|HTTPPort|HTTPSEnable|HTTPSProxy|HTTPSPort|SOCKSEnable|SOCKSProxy|SOCKSPort|ProxyAutoConfigEnable)\s*:\s*(.*?)\s*$", line)
            if match:
                key, value = match.groups()
                os_proxy[key] = value[:256] if not key.endswith("Proxy") else safe_proxy(value)
        capability("os-proxy", True, "macOS system configuration; individual applications may differ")
    else:
        capability("os-proxy", False, "scutil read unavailable")
elif platform.system() == "Linux" and shutil.which("gsettings"):
    text = command([shutil.which("gsettings"), "get", "org.gnome.system.proxy", "mode"])
    if text is not None:
        os_proxy["gnome_mode"] = text.strip()[:64]
        capability("os-proxy", True, "GNOME setting only; not a universal Linux proxy")
    else:
        capability("os-proxy", False, "desktop proxy setting unavailable")
else:
    capability("os-proxy", False, "no supported system proxy reader")
result["os_proxy"] = os_proxy

result["dns_config"], result["interfaces"], result["policy_routing"] = [], [], []
if not request.get("request_only"):
    if platform.system() == "Darwin":
        scutil = shutil.which("scutil")
        text = command([scutil, "--dns"]) if scutil else None
        if text:
            result["dns_config"] = sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", text)))[:32]
        ifconfig = shutil.which("ifconfig")
        text = command([ifconfig, "-a"]) if ifconfig else None
        if text:
            current = None
            for line in text.splitlines():
                match = re.match(r"^(\S+): flags=.*?<([^>]*)>", line)
                if match and len(result["interfaces"]) < 64:
                    name, flags = match.groups()
                    current = {"name": name, "state": "UP" if "UP" in flags.split(",") else "DOWN", "kind": "tunnel" if name.startswith(("utun", "tun", "tap")) else "interface", "addresses": []}
                    result["interfaces"].append(current)
                elif current is not None:
                    address = re.match(r"\s*inet6?\s+(\S+)", line)
                    if address and len(current["addresses"]) < 8:
                        current["addresses"].append(address.group(1))
    elif platform.system() == "Linux":
        try:
            with open("/etc/resolv.conf", "r") as source:
                text = source.read(16384)
            result["dns_config"] = re.findall(r"(?m)^\s*nameserver\s+(\S+)", text)[:32]
        except OSError:
            pass
        resolvectl = shutil.which("resolvectl")
        text = command([resolvectl, "dns"]) if resolvectl else None
        if text:
            for line in text.splitlines()[:32]:
                if ":" in line:
                    for item in line.split(":", 1)[1].split():
                        try:
                            ipaddress.ip_address(item.split("%", 1)[0])
                            if item not in result["dns_config"]:
                                result["dns_config"].append(item)
                        except ValueError:
                            pass
        ip_tool = shutil.which("ip")
        text = command([ip_tool, "-j", "address", "show"]) if ip_tool else None
        try:
            for row in json.loads(text)[:64]:
                result["interfaces"].append({"name": row.get("ifname", ""), "state": row.get("operstate", ""), "kind": row.get("linkinfo", {}).get("info_kind", row.get("link_type", "")), "addresses": [item.get("local", "") for item in row.get("addr_info", [])[:8]]})
        except (TypeError, ValueError, AttributeError):
            pass
        text = command([ip_tool, "-j", "rule", "show"]) if ip_tool else None
        try:
            for row in json.loads(text)[:32]:
                safe = {key: row[key] for key in ("priority", "src", "dst", "table", "fwmark", "iif", "oif") if key in row}
                result["policy_routing"].append(json.dumps(safe, sort_keys=True))
        except (TypeError, ValueError):
            pass
    capability("dns-config", bool(result["dns_config"]), "passive OS resolver configuration; scoped resolver selection may differ")
    capability("interfaces", bool(result["interfaces"]), "passive interface inventory; an active tunnel interface alone does not prove request interception")

if observe or request.get("request_only"):
    result["dns"]["error"] = "not queried in this inventory/request phase"
else:
    values = queue.Queue()
    def resolve():
        try:
            addresses = sorted(set(item[4][0] for item in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)))
            values.put(addresses[:16])
        except OSError:
            values.put(None)
    worker = threading.Thread(target=resolve, daemon=True)
    worker.start()
    try:
        addresses = values.get(timeout=3)
        if addresses is None:
            result["dns"]["error"] = "native DNS resolution failed"
        else:
            result["dns"]["addresses"] = addresses
    except queue.Empty:
        result["dns"]["error"] = "native DNS resolution timed out"

route_tool = shutil.which("ip") if platform.system() == "Linux" else shutil.which("route") if platform.system() == "Darwin" else None
capability("route", bool(route_tool), "read-only route lookup; TUN and policy routing may affect traffic")
for address in result["dns"]["addresses"][:4]:
    entry = {"destination": address}
    if route_tool and platform.system() == "Linux":
        text = command([route_tool, "-j", "route", "get", address])
        try:
            row = json.loads(text)[0]
            entry.update({"interface": str(row.get("dev", "")), "gateway": str(row.get("gateway", "")), "source": str(row.get("prefsrc", row.get("src", "")))})
        except (TypeError, ValueError, KeyError, IndexError):
            entry["error"] = "route lookup unavailable"
    elif route_tool:
        text = command([route_tool, "-n", "get", address])
        if text:
            for key in ("gateway", "interface"):
                match = re.search(r"^\s*" + key + r":\s*(\S+)", text, re.M)
                if match:
                    entry[key] = match.group(1)[:256]
        else:
            entry["error"] = "route lookup unavailable"
    else:
        entry["error"] = "route tool unavailable"
    result["routes"].append(entry)

curl = shutil.which("curl")
capability("curl", bool(curl), "fixed HEAD requests; startup curlrc disabled; redirects disabled")
if curl and not observe and not request.get("inventory_only"):
    format_keys = ["http_code", "time_namelookup", "time_connect", "time_appconnect", "time_starttransfer", "time_total", "local_ip", "local_port", "remote_ip", "remote_port"]
    output_format = "\n".join("%{" + key + "}" for key in format_keys)
    def head(source, bypass):
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence = {"source": source, "status": "unavailable", "started_at": started, "note": ("No application proxy does not bypass TUN, routing rules or transparent interception." if bypass else "Uses curl's process environment; does not model browsers, services or GUI applications.") + " DNS/connect/TLS/first-byte times are cumulative milestones since request start, not additive phase durations."}
        args = [curl, "-q", "--silent", "--show-error", "--head", "--max-time", "5", "--connect-timeout", "3", "--max-redirs", "0", "--output", os.devnull, "--write-out", output_format, "--config", "-"]
        if bypass:
            args += ["--noproxy", "*"]
        config = "url = " + json.dumps(request["url"], ensure_ascii=False) + "\n"
        try:
            completed = subprocess.run(args, input=config.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=6, check=False)
            text = completed.stdout.decode("ascii", "replace") if len(completed.stdout) <= 4096 else ""
            fields = dict(zip(format_keys, text.splitlines()))
            evidence["http_status"] = int(fields.get("http_code", "0"))
            for key, dest in (("time_namelookup", "dns_milliseconds"), ("time_connect", "connect_milliseconds"), ("time_appconnect", "tls_milliseconds"), ("time_starttransfer", "first_byte_milliseconds"), ("time_total", "milliseconds")):
                evidence[dest] = float(fields.get(key, "0")) * 1000
            for side in ("local", "remote"):
                ip = fields.get(side + "_ip", "")
                number = fields.get(side + "_port", "0")
                if ip and number != "0":
                    evidence[side + "_address"] = ("[" + ip + "]" if ":" in ip else ip) + ":" + number
            if completed.returncode == 0 and evidence["http_status"] > 0:
                evidence["status"] = "http-response"
                if evidence["http_status"] >= 400:
                    evidence["note"] += " An HTTP error is still a response, not a network timeout."
            else:
                evidence["status"] = "failed"
                evidence["error"] = "request timed out" if completed.returncode == 28 else "request failed (curl exit " + str(completed.returncode) + ")"
        except subprocess.TimeoutExpired:
            evidence.update({"status": "failed", "error": "request timed out"})
        except (OSError, ValueError):
            evidence.update({"status": "failed", "error": "curl evidence unavailable"})
        evidence["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return evidence
    kinds = [request["request_kind"]] if request.get("request_kind") else ["environment", "no-application-proxy"]
    result["requests"] = [head(kind, kind == "no-application-proxy") for kind in kinds]
elif not observe and not request.get("inventory_only"):
    result["requests"] = [{"source": source, "status": "unavailable", "error": "curl unavailable"} for source in ("environment", "no-application-proxy")]

json.dump(result, sys.stdout, ensure_ascii=True, separators=(",", ":"))
