#!/usr/bin/env python3
"""CodeGate Infra Shield agent — read-only.

Collects security-relevant facts about this server and sends them to CodeGate:
listening ports, a few sshd settings, firewall / Fail2ban / CrowdSec status,
Docker container settings and pending security updates.

It never modifies the system, never sends file contents, environment
variables, secrets or logs, and never scans other hosts. Run it with
--dry-run to see exactly what would be sent.

Usage:
  sudo CODEGATE_TOKEN=cg_srv_... python3 codegate-agent.py
  sudo python3 codegate-agent.py --token-file /etc/codegate/agent.token
  python3 codegate-agent.py --dry-run
"""

import argparse
import glob
import json
import os
import re
import shutil
import ssl
import time
import socket
import subprocess
import sys
import urllib.error
import urllib.request

VERSION = "1.2.0"
DEFAULT_URL = "https://codegate-api.vercel.app"


def run(cmd, timeout=20):
    """Run a command; return stdout, or None if unavailable / failed."""
    if not shutil.which(cmd[0]):
        return None
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
    out = run(["ufw", "status"])
    if out is not None:
        ufw = "active" if "Status: active" in out else "inactive"
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
    return {"ufw": ufw, "nftablesRules": nft_rules, "iptablesRules": ipt_rules}


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


def docker():
    ids = run(["docker", "ps", "-q"])
    if ids is None:
        return None
    ids = ids.split()
    if not ids:
        return {"containers": []}
    raw = run(["docker", "inspect"] + ids, timeout=60)
    if raw is None:
        return None
    containers = []
    for c in json.loads(raw):
        host = c.get("HostConfig") or {}
        cfg = c.get("Config") or {}
        ports = []
        for bindings in ((c.get("NetworkSettings") or {}).get("Ports") or {}).values():
            for b in bindings or []:
                if str(b.get("HostPort", "")).isdigit():
                    ports.append({"hostIp": b.get("HostIp") or "", "hostPort": int(b["HostPort"])})
        mounts = [m.get("Source", "") for m in c.get("Mounts") or []]
        containers.append(
            {
                "name": (c.get("Name") or "").lstrip("/")[:255],
                "image": (cfg.get("Image") or "")[:500],
                "user": (cfg.get("User") or "")[:100],
                "privileged": bool(host.get("Privileged")),
                "dockerSocketMounted": any(s.endswith("docker.sock") for s in mounts),
                "capAdd": [str(x)[:60] for x in host.get("CapAdd") or []],
                "publishedPorts": ports,
                "readOnlyRootfs": bool(host.get("ReadonlyRootfs")),
                "memoryLimit": int(host.get("Memory") or 0),
            }
        )
    return {"containers": containers}


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
        return {"manager": "apt", "pendingSecurity": pending, "autoUpdates": auto}
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


def _probe_tls(port, version=None):
    """Handshake with 127.0.0.1:port; returns (protocol, der_cert) or None."""
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
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                return tls.version(), tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None


def _cert_facts(der):
    """(days until expiry, self-signed) from a DER certificate, stdlib only."""
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
        return days, info.get("subject") == info.get("issuer")
    except Exception:  # pylint: disable=broad-except
        return None, None


def tls_audit(listening_sockets):
    """TLS Audit: probes local HTTPS listeners only (never another host)."""
    ports = sorted({l["port"] for l in listening_sockets if l["proto"] == "tcp" and l["port"] in TLS_PORTS})
    results = []
    for port in ports:
        probe = _probe_tls(port)
        if not probe:
            continue
        protocol, der = probe
        days, self_signed = _cert_facts(der) if der else (None, None)
        legacy = None
        for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            r = _probe_tls(port, version)
            if r == "unsupported":
                continue  # this client cannot even offer it: inconclusive
            legacy = bool(r) or bool(legacy)
        results.append({
            "port": port,
            "protocol": protocol,
            "legacyAccepted": legacy,
            "certExpiresInDays": days,
            "selfSigned": self_signed,
        })
    return results


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


def collect():
    sockets = listening()
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
        "docker": docker(),
        "updates": updates(),
        "tls": tls_audit(sockets),
        "backups": backups(),
    }


def main():
    p = argparse.ArgumentParser(description="CodeGate Infra Shield agent (read-only)")
    p.add_argument("--url", default=os.environ.get("CODEGATE_URL", DEFAULT_URL))
    p.add_argument("--token-file", help="file containing the cg_srv_ agent token")
    p.add_argument("--dry-run", action="store_true", help="print the report, send nothing")
    args = p.parse_args()

    report = collect()
    if args.dry_run:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    token = os.environ.get("CODEGATE_TOKEN", "")
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as f:
            token = f.read().strip()
    if not token.startswith("cg_srv_"):
        print("CodeGate: token manquant (CODEGATE_TOKEN ou --token-file).", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("CodeGate: conseil — lancez en root pour auditer SSH, le firewall et Docker.",
              file=sys.stderr)

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
            print(f"CodeGate: rapport envoyé — score {body.get('score')}/100, "
                  f"{body.get('findings')} point(s) à corriger.")
            return 0
    except urllib.error.HTTPError as e:
        print(f"CodeGate: refusé ({e.code}) — vérifiez le token.", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"CodeGate: API injoignable ({e.reason}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
