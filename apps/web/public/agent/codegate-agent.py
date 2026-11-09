#!/usr/bin/env python3
"""CodeGate Infra Shield agent — read-only.

Collects security-relevant facts about this server and sends them to CodeGate:
listening ports, a few sshd settings, firewall / Fail2ban / CrowdSec status,
Docker container settings and pending security updates.

It never modifies the system, never sends file contents, environment
variable values, secrets or logs, and never scans other hosts: TLS and HTTP
probes target 127.0.0.1 only, with the hostnames configured on this server.
Run it with --dry-run to see exactly what would be sent.

Usage:
  sudo CODEGATE_TOKEN=cg_srv_... python3 codegate-agent.py
  sudo python3 codegate-agent.py --token-file /etc/codegate/agent.token
  python3 codegate-agent.py --dry-run
  # cron every 15 min: runs only when an audit is due or asked from CodeGate
  python3 codegate-agent.py --token-file ... --scheduled
  # least privilege: a dedicated user + the sudoers rules shown by CodeGate
  python3 codegate-agent.py --token-file ... --sudo

Which probes need root (P2-6): `sshd -T` (effective SSH settings), `ufw` /
`nft` / `iptables` (firewall rules) and the Docker CLI (equivalent to root
through the socket). Everything else — listening sockets, /proc, TLS probes,
cron files, daemon.json — works as an unprivileged user. With --sudo, only
those commands go through `sudo -n`, as allowed by the sudoers file.
"""

import argparse
import glob
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import warnings

VERSION = "2.0.1"
DEFAULT_URL = "https://codegate-api.vercel.app"

# Commands that need root; with --sudo they run through `sudo -n` (P2-6).
PRIVILEGED = {"sshd", "ufw", "nft", "iptables", "docker"}
USE_SUDO = False
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def run(cmd, timeout=20):
    """Run a command; return stdout, or None if unavailable / failed."""
    # A fixed system PATH, never the inherited one: the agent may run as root
    # (cron, sudo), and a writable directory early in $PATH would let anyone
    # substitute `docker` or `sshd`. It also covers the sbin directories that
    # cron's PATH lacks (sshd, ufw, nft, iptables).
    exe = shutil.which(cmd[0], path=SYSTEM_PATH)
    if not exe:
        return None
    cmd = [exe] + list(cmd[1:])
    if USE_SUDO and os.path.basename(exe) in PRIVILEGED:
        cmd = ["sudo", "-n"] + cmd
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def os_name():
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')[:120]
    except OSError:
        pass
    return None


def listening():
    out = run(["ss", "-H", "-tuln", "-p"]) or run(["ss", "-H", "-tuln"])
    sockets = []
    if out is None:
        return sockets
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        if proto not in ("tcp", "udp"):
            continue
        local = parts[4]
        if ":" not in local:
            continue
        address, port = local.rsplit(":", 1)
        if not port.isdigit():
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        sockets.append(
            {
                "proto": proto,
                "address": address.strip("[]").split("%")[0][:64] or "*",
                "port": int(port),
                "process": m.group(1)[:80] if m else None,
            }
        )
    return sockets


def _yes(value):
    if value is None:
        return None
    return value.lower() == "yes"


def ssh_settings():
    keys = ("permitrootlogin", "passwordauthentication", "pubkeyauthentication", "maxauthtries")
    found = {}
    effective = run(["sshd", "-T"]) or run(["/usr/sbin/sshd", "-T"])
    if effective is not None:
        for line in effective.splitlines():
            k, _, v = line.partition(" ")
            if k in keys:
                found[k] = v.strip()
    else:
        files = ["/etc/ssh/sshd_config"] + sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))
        if not os.path.exists(files[0]):
            return None
        # sshd keeps the first value it reads; included files come first.
        for path in files[1:] + files[:1]:
            try:
                with open(path, encoding="utf-8") as f:
                    for raw in f:
                        line = raw.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.lower().startswith("match "):
                            break
                        k, _, v = line.partition(" ")
                        k = k.lower()
                        if k in keys and k not in found:
                            found[k] = v.strip()
            except OSError:
                continue
    max_tries = found.get("maxauthtries")
    return {
        "permitRootLogin": found.get("permitrootlogin"),
        "passwordAuthentication": _yes(found.get("passwordauthentication")),
        "pubkeyAuthentication": _yes(found.get("pubkeyauthentication")),
        "maxAuthTries": int(max_tries) if max_tries and max_tries.isdigit() else None,
    }


def firewall():
    ufw = None
    ufw_allowed = None
    out = run(["ufw", "status"])
    if out is not None:
        ufw = "active" if "Status: active" in out else "inactive"
        ufw_allowed = set()
        # "443/tcp   ALLOW   Anywhere" / "22 (v6)  ALLOW IN  Anywhere (v6)"
        for line in out.splitlines():
            m = re.match(r"^(\d+)(?:/(?:tcp|udp))?(?:\s+\(v6\))?\s+ALLOW(?:\s+IN)?\s+Anywhere", line.strip())
            if m:
                ufw_allowed.add(int(m.group(1)))
        ufw_allowed = sorted(ufw_allowed)
    nft = run(["nft", "list", "ruleset"])
    nft_rules = None
    if nft is not None:
        nft_rules = sum(
            1 for l in nft.splitlines()
            if re.search(r"\b(accept|drop|reject)\b", l) and "policy" not in l
        )
    ipt = run(["iptables", "-S"])
    ipt_rules = None
    if ipt is not None:
        ipt_rules = sum(1 for l in ipt.splitlines() if l.startswith("-A"))
    return {"ufw": ufw, "ufwAllowed": ufw_allowed, "nftablesRules": nft_rules, "iptablesRules": ipt_rules}


def service_active(name):
    if not shutil.which("systemctl"):
        return None
    out = subprocess.run(
        ["systemctl", "is-active", name], capture_output=True, text=True, check=False
    )
    state = out.stdout.strip()
    if state in ("active", "activating", "reloading"):
        return True
    if state in ("inactive", "failed", "deactivating"):
        return False
    return None  # systemd not running (container) — unknown, not "absent"


SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|DSN)", re.I)
NOT_SECRET_VALUE = re.compile(r"^(|true|false|yes|no|0|1|/run/secrets/.*|changeme)$", re.I)
SOCKET_PROXY_IMAGE = re.compile(r"(docker-socket-proxy|socket-proxy|dockerproxy)(:|@|$)")
HOST_RULE = re.compile(r"Host(?:SNI)?\(([^)]*)\)")
# Traefik file provider: "<name>:\n  basicAuth:\n    usersFile: …" (YAML) or
# "[http.middlewares.<name>.basicAuth]\n usersFile = …" (TOML).
FILE_PROVIDER_USERS = (
    re.compile(r"^[ \t]*([\w-]+):[ \t]*\n[ \t]+basicAuth:[ \t]*\n(?:[^\n]*\n){0,4}?[ \t]*usersFile:[ \t]*[\"']?([^\"'\n]+)", re.M | re.I),
    re.compile(r"\[http\.middlewares\.([\w-]+)\.basicAuth\][ \t]*\n(?:[^\n]*\n){0,4}?[ \t]*usersFile[ \t]*=[ \t]*[\"']([^\"']+)", re.I),
)


def _effective_uid(pid):
    """Effective UID of the container's main process, read from /proc (P0-4)."""
    try:
        with open(f"/proc/{int(pid)}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[2])
    except (OSError, ValueError, IndexError):
        pass
    return None


def _secret_env_names(env):
    """Names (never values) of variables holding a literal secret (P1-4)."""
    names = []
    for item in env or []:
        name, _, value = item.partition("=")
        if name.endswith("_FILE") or not SECRET_NAME.search(name):
            continue
        if NOT_SECRET_VALUE.match(value.strip()):
            continue
        names.append(name[:100])
    return sorted(set(names))[:100]


def _host_path(container, inner_path):
    """Map a path seen inside a container to the host, through its mounts."""
    best = None
    for m in container.get("Mounts") or []:
        dest = (m.get("Destination") or "").rstrip("/")
        if dest and (inner_path == dest or inner_path.startswith(dest + "/")):
            if best is None or len(dest) > len(best[0]):
                best = (dest, m.get("Source") or "")
    if best is None:
        return None
    return best[1] + inner_path[len(best[0]):]


def _file_provider_users_files(proxy):
    """middleware name -> usersFile, from Traefik dynamic config files on the host."""
    found = {}
    if proxy is None:
        return found
    for m in proxy.get("Mounts") or []:
        src = m.get("Source") or ""
        if not src or src.endswith(".sock") or not os.path.exists(src):
            continue
        paths = [src] if os.path.isfile(src) else glob.glob(os.path.join(src, "**", "*.y*ml"), recursive=True) + glob.glob(os.path.join(src, "**", "*.toml"), recursive=True)
        for path in paths[:200]:
            try:
                if os.path.getsize(path) > 300_000:
                    continue
                with open(path, encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                continue
            for pattern in FILE_PROVIDER_USERS:
                for mm in pattern.finditer(text):
                    found[mm.group(1)] = mm.group(2).strip()
    return found


def _route_facts(c, labels, proxy, file_users):
    """Hostnames routed to a container and the state of their auth (P1-3)."""
    hosts, middlewares = [], set()
    for key, value in labels.items():
        if re.match(r"^traefik\.http\.routers\.[^.]+\.rule$", key):
            for group in HOST_RULE.findall(value):
                hosts += [h.strip(" `'\"") for h in group.split(",") if h.strip(" `'\"")]
        elif re.match(r"^traefik\.http\.routers\.[^.]+\.middlewares$", key):
            middlewares |= {m.strip() for m in value.split(",") if m.strip()}
    if not hosts:
        return [], None
    auth = "none"
    for ref in middlewares:
        name, _, provider = ref.partition("@")
        prefix = f"traefik.http.middlewares.{name}."
        kinds = [k[len(prefix):].lower() for k in labels if k.startswith(prefix)]
        if any(k.startswith(("forwardauth", "digestauth")) for k in kinds) or any(k == "basicauth.users" for k in kinds):
            auth = "ok"
            continue
        users_file = labels.get(prefix + "basicauth.usersfile") or labels.get(prefix + "basicAuth.usersFile")
        if users_file is None and provider == "file":
            users_file = file_users.get(name)
        if users_file is not None:
            host_path = _host_path(proxy, users_file) if proxy else None
            if host_path is None or not os.path.exists(host_path):
                return sorted(set(hosts))[:50], "broken"
            auth = "ok"
    return sorted(set(hosts))[:50], auth


def _daemon_config():
    try:
        with open("/etc/docker/daemon.json", encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        cfg = {}
    except (OSError, ValueError):
        return None
    return {
        "usernsRemap": bool(cfg.get("userns-remap")),
        "liveRestore": bool(cfg.get("live-restore")),
        "noNewPrivileges": bool(cfg.get("no-new-privileges")),
        "logMaxSize": bool((cfg.get("log-opts") or {}).get("max-size")) or cfg.get("log-driver") in ("journald", "local", "none"),
    }


def _env_files(raw):
    """.env files of compose projects: path and permissions only, never content."""
    dirs = {((c.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.project.working_dir") for c in raw}
    files = []
    for d in sorted(x for x in dirs if x):
        for name in (".env", ".env.production", ".env.prod"):
            path = os.path.join(d, name)
            try:
                mode = os.stat(path).st_mode
            except OSError:
                continue
            files.append({
                "path": path[:500],
                "mode": oct(stat.S_IMODE(mode))[2:],
                "worldReadable": bool(mode & stat.S_IROTH),
            })
    return files[:100]


def docker():
    ids = run(["docker", "ps", "-q"])
    if ids is None:
        return None
    ids = ids.split()
    if not ids:
        return {"containers": [], "daemon": _daemon_config(), "envFiles": []}
    raw = run(["docker", "inspect"] + ids, timeout=60)
    if raw is None:
        return None
    raw = json.loads(raw)
    proxy = next((c for c in raw if "traefik" in ((c.get("Config") or {}).get("Image") or "")), None)
    file_users = _file_provider_users_files(proxy)
    containers = []
    for c in raw:
        host = c.get("HostConfig") or {}
        cfg = c.get("Config") or {}
        labels = cfg.get("Labels") or {}
        image = (cfg.get("Image") or "")[:500]
        ports = []
        for bindings in ((c.get("NetworkSettings") or {}).get("Ports") or {}).values():
            for b in bindings or []:
                if str(b.get("HostPort", "")).isdigit():
                    ports.append({"hostIp": b.get("HostIp") or "", "hostPort": int(b["HostPort"])})
        mounts = [
            {
                "source": (m.get("Source") or "")[:500],
                "destination": (m.get("Destination") or "")[:500],
                "rw": bool(m.get("RW")),
            }
            for m in c.get("Mounts") or []
            if m.get("Type") in ("bind", None)
        ]
        hosts, route_auth = _route_facts(c, labels, proxy, file_users)
        env = cfg.get("Env") or []
        proxy_post = None
        if SOCKET_PROXY_IMAGE.search(image):
            values = dict(e.partition("=")[::2] for e in env)
            proxy_post = values.get("POST", "0").strip() == "1"
        entry = {
            "name": (c.get("Name") or "").lstrip("/")[:255],
            "image": image,
            "user": (cfg.get("User") or "")[:100],
            "privileged": bool(host.get("Privileged")),
            "dockerSocketMounted": any(m["source"].endswith("docker.sock") for m in mounts),
            "capAdd": [str(x)[:60] for x in host.get("CapAdd") or []],
            "capDrop": [str(x)[:60] for x in host.get("CapDrop") or []],
            "publishedPorts": ports,
            "readOnlyRootfs": bool(host.get("ReadonlyRootfs")),
            "memoryLimit": int(host.get("Memory") or 0),
            "mounts": mounts[:200],
            "effectiveUid": _effective_uid((c.get("State") or {}).get("Pid") or 0),
            "networkMode": str(host.get("NetworkMode") or "")[:100],
            "networks": sorted(((c.get("NetworkSettings") or {}).get("Networks") or {}).keys())[:50],
            "noNewPrivileges": any("no-new-privileges" in str(o) for o in host.get("SecurityOpt") or []),
            "secretEnvNames": _secret_env_names(env),
            "socketProxyPost": proxy_post,
        }
        if hosts:
            entry["routedHosts"] = hosts
            entry["routeAuth"] = route_auth
        containers.append(entry)
    return {"containers": containers, "daemon": _daemon_config(), "envFiles": _env_files(raw)}


def updates():
    if shutil.which("apt-get"):
        sim = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=120)
        pending = None
        if sim is not None:
            pending = sum(
                1 for l in sim.splitlines() if l.startswith("Inst ") and "-security" in l
            )
        auto = None
        cfg = "/etc/apt/apt.conf.d/20auto-upgrades"
        if os.path.exists(cfg):
            with open(cfg, encoding="utf-8") as f:
                auto = bool(re.search(r'Unattended-Upgrade\s+"1"', f.read()))
        elif shutil.which("dpkg"):
            auto = False
        # Enabled is not enough: has it actually run lately? (P1-7)
        last_run = None
        try:
            stamp = os.path.getmtime("/var/lib/apt/periodic/unattended-upgrades-stamp")
            last_run = int((time.time() - stamp) // 86400)
        except OSError:
            pass
        return {"manager": "apt", "pendingSecurity": pending, "autoUpdates": auto,
                "autoUpdatesLastRunDays": last_run}
    if shutil.which("dnf"):
        out = run(["dnf", "-q", "updateinfo", "list", "--security"], timeout=120)
        pending = len([l for l in out.splitlines() if l.strip()]) if out is not None else None
        enabled = subprocess.run(
            ["systemctl", "is-enabled", "dnf-automatic.timer"],
            capture_output=True, text=True, check=False,
        ).stdout.strip() if shutil.which("systemctl") else ""
        return {
            "manager": "dnf",
            "pendingSecurity": pending,
            "autoUpdates": enabled == "enabled" if enabled else None,
        }
    return {"manager": None, "pendingSecurity": None, "autoUpdates": None}


TLS_PORTS = (443, 8443, 9443)


def _legacy_versions():
    """TLS 1.0 / 1.1 constants without the DeprecationWarning they raise (P2-4)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)


def _probe_tls(port, version=None, sni=None):
    """Handshake with 127.0.0.1:port (SNI = sni); returns (protocol, der_cert) or None."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if version is not None:
            try:
                ctx.minimum_version = version
                ctx.maximum_version = version
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except (ValueError, ssl.SSLError):
                return "unsupported"
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            # No SNI at all when no hostname is known: the proxy's default certificate.
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                return tls.version(), tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return None


def _trusted(port, sni):
    """Chain and hostname validated against the system trust store, on loopback."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni):
                return True
    except ssl.SSLCertVerificationError:
        return False
    except (OSError, ssl.SSLError):
        return None


def _security_headers(port, sni):
    """HSTS / CSP / X-Frame-Options / X-Content-Type-Options on GET / (P1-6)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                tls.sendall(
                    f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: codegate-agent/{VERSION}\r\nConnection: close\r\n\r\n".encode()
                )
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
    except (OSError, ssl.SSLError):
        return None
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").lower()
    if not head.startswith("http/"):
        return None
    names = {line.split(":", 1)[0].strip() for line in head.split("\r\n")[1:] if ":" in line}
    return {
        "hsts": "strict-transport-security" in names,
        "csp": "content-security-policy" in names,
        "frameOptions": "x-frame-options" in names,
        "contentTypeOptions": "x-content-type-options" in names,
    }


def _cert_facts(der):
    """(days until expiry, self-signed, issuer) from a DER certificate, stdlib only."""
    try:
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            path = f.name
        try:
            info = ssl._ssl._test_decode_cert(path)  # noqa: SLF001 (stdlib decoder)
        finally:
            os.unlink(path)
        expires = ssl.cert_time_to_seconds(info["notAfter"])
        days = int((expires - time.time()) // 86400)
        issuer = dict(x[0] for x in info.get("issuer") or ())
        name = issuer.get("organizationName") or issuer.get("commonName")
        return days, info.get("subject") == info.get("issuer"), (name or "")[:200] or None
    except Exception:  # pylint: disable=broad-except
        return None, None, None


def configured_hostnames(docker_facts):
    """Domains this server serves: Traefik routes, nginx server_name, Caddyfile (P0-2)."""
    hosts = set()
    for c in (docker_facts or {}).get("containers") or []:
        hosts |= set(c.get("routedHosts") or [])
    for path in glob.glob("/etc/nginx/sites-enabled/*") + glob.glob("/etc/nginx/conf.d/*.conf"):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for m in re.finditer(r"^\s*server_name\s+([^;]+);", f.read(), re.M):
                    hosts |= set(m.group(1).split())
        except OSError:
            continue
    for path in ("/etc/caddy/Caddyfile",):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for m in re.finditer(r"^([a-z0-9.*-]+\.[a-z]{2,}(?:\s*,\s*[a-z0-9.*-]+\.[a-z]{2,})*)\s*\{", f.read(), re.M | re.I):
                    hosts |= {h.strip() for h in m.group(1).split(",")}
        except OSError:
            continue
    valid = re.compile(r"^(?=.{1,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$", re.I)
    return sorted(h.lower() for h in hosts if valid.match(h) and h not in ("localhost", "_"))[:20]


def tls_audit(listening_sockets, hostnames):
    """TLS Audit: local HTTPS listeners only, probed for each configured hostname."""
    ports = sorted({l["port"] for l in listening_sockets if l["proto"] == "tcp" and l["port"] in TLS_PORTS})
    results = []
    for port in ports:
        for sni in [None] + (hostnames if port == 443 else []):
            probe = _probe_tls(port, sni=sni)
            if not probe or probe == "unsupported":
                continue
            protocol, der = probe
            days, self_signed, issuer = _cert_facts(der) if der else (None, None, None)
            legacy = None
            if sni is None:
                for version in _legacy_versions():
                    r = _probe_tls(port, version)
                    if r == "unsupported":
                        continue  # this client cannot even offer it: inconclusive
                    legacy = bool(r) or bool(legacy)
            entry = {
                "port": port,
                "protocol": protocol,
                "legacyAccepted": legacy,
                "certExpiresInDays": days,
                "selfSigned": self_signed,
                "issuer": issuer,
                "sni": sni,
            }
            if sni:
                entry["trusted"] = _trusted(port, sni)
                entry["headers"] = _security_headers(port, sni)
            results.append(entry)
    return results[:100]


BACKUP_TOOLS = ("pg_dump", "pg_dumpall", "pgbackrest", "barman", "mysqldump", "mariadb-dump",
                "xtrabackup", "mongodump", "restic", "borg", "rclone", "duplicity", "rsync",
                "rsnapshot", "kopia", "codegate-backup")


def backups():
    """Backup Discovery: only tool names are reported, never command lines
    (they may contain credentials)."""
    sources = (
        ["/etc/crontab"]
        + glob.glob("/etc/cron.d/*")
        + glob.glob("/etc/cron.daily/*")
        + glob.glob("/var/spool/cron/crontabs/*")
        + glob.glob("/var/spool/cron/*")
        + glob.glob("/etc/systemd/system/*.service")
    )
    jobs, tools = 0, set()
    for path in sources:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read(200_000)
        except OSError:
            continue
        found = {t for t in BACKUP_TOOLS if t in text}
        if found or "backup" in os.path.basename(path).lower():
            jobs += 1
            tools |= found
    return {
        "jobs": jobs,
        "tools": sorted(tools)[:30],
        "codegateReporting": "codegate-backup" in tools,
    }


def host_accounts():
    """UID-0 accounts and passwordless sudo principals — names only (P1-7)."""
    uid0 = []
    try:
        with open("/etc/passwd", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) > 3 and parts[2] == "0":
                    uid0.append(parts[0][:64])
    except OSError:
        pass
    nopasswd, readable = set(), False
    for path in ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*")):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read(200_000)
            readable = True
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            m = re.match(r"^(%?[\w.-]+)\s+\S+\s*=\s*(?:\([^)]*\)\s*)?NOPASSWD:\s*ALL\s*$", line)
            if m:
                nopasswd.add(m.group(1)[:64])
    return {"uid0Accounts": uid0[:50], "passwordlessSudo": sorted(nopasswd)[:50] if readable else None}


def collect():
    sockets = listening()
    docker_facts = docker()
    return {
        "agentVersion": VERSION,
        "hostname": socket.gethostname()[:255],
        "os": os_name(),
        "listening": sockets,
        "ssh": ssh_settings(),
        "firewall": firewall(),
        "bruteforce": {
            "fail2ban": service_active("fail2ban"),
            "crowdsec": service_active("crowdsec"),
        },
        "docker": docker_facts,
        "updates": updates(),
        "host": host_accounts(),
        "tls": tls_audit(sockets, configured_hostnames(docker_facts)),
        "backups": backups(),
    }


def _due(url, token):
    """--scheduled: ask CodeGate whether an audit is due or was requested (P2-7)."""
    req = urllib.request.Request(
        url.rstrip("/") + "/api/v1/agent/pending",
        headers={"authorization": "Bearer " + token, "user-agent": "codegate-agent/" + VERSION},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            return bool(json.loads(res.read().decode("utf-8")).get("run"))
    except (urllib.error.URLError, ValueError):
        return True  # API unreachable: audit anyway, the report call will tell


def main():
    global USE_SUDO  # pylint: disable=global-statement
    p = argparse.ArgumentParser(description="CodeGate Infra Shield agent (read-only)")
    p.add_argument("--url", default=os.environ.get("CODEGATE_URL", DEFAULT_URL))
    p.add_argument("--token-file", help="file containing the cg_srv_ agent token")
    p.add_argument("--dry-run", action="store_true", help="print the report, send nothing")
    p.add_argument("--scheduled", action="store_true",
                   help="run only if an audit is due or was requested from CodeGate")
    p.add_argument("--sudo", action="store_true",
                   help="unprivileged user: run only the probes that need root through sudo -n")
    args = p.parse_args()
    USE_SUDO = args.sudo and os.geteuid() != 0

    token = os.environ.get("CODEGATE_TOKEN", "")
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as f:
            token = f.read().strip()

    if args.dry_run:
        print(json.dumps(collect(), indent=2, ensure_ascii=False))
        return 0

    if not token.startswith("cg_srv_"):
        print("CodeGate: token manquant (CODEGATE_TOKEN ou --token-file).", file=sys.stderr)
        return 2
    if args.scheduled and not _due(args.url, token):
        return 0
    if os.geteuid() != 0 and not USE_SUDO:
        print("CodeGate: conseil — lancez en root, ou avec --sudo et les règles sudoers, "
              "pour auditer SSH, le firewall et Docker.", file=sys.stderr)

    report = collect()
    req = urllib.request.Request(
        args.url.rstrip("/") + "/api/v1/agent/report",
        data=json.dumps(report).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "authorization": "Bearer " + token,
            "user-agent": "codegate-agent/" + VERSION,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            body = json.loads(res.read().decode("utf-8"))
            score, prev = body.get("score"), body.get("previousScore")
            delta = ""
            if isinstance(score, int) and isinstance(prev, int) and score != prev:
                delta = f" ({score - prev:+d} depuis le dernier audit)"
            fixed = f", {body['resolved']} corrigé(s)" if body.get("resolved") else ""
            print(f"CodeGate: rapport envoyé — score {score}/100{delta}, "
                  f"{body.get('findings')} point(s) à corriger{fixed}.")
            return 0
    except urllib.error.HTTPError as e:
        print(f"CodeGate: refusé ({e.code}) — vérifiez le token.", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"CodeGate: API injoignable ({e.reason}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
