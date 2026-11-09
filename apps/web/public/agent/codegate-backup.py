#!/usr/bin/env python3
"""CodeGate Backup Shield helper.

Declares backup runs to CodeGate, re-checks the integrity of stored copies
and tests restores in a throwaway, network-isolated container. CodeGate only
ever receives metadata (hash, size, protections, timings) — never the backup.

  report       after each backup: hash + detected encryption + protections
  verify       re-hash a stored copy and compare with the recorded backups
  restore-test restore a PostgreSQL dump into a disposable container
               (--network none, deleted afterwards; production is never used)

Token: --token-file FILE or CODEGATE_BACKUP_TOKEN. API: CODEGATE_URL.
"""

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

VERSION = "1.0.1"
DEFAULT_URL = "https://codegate-api.vercel.app"


def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_encryption(path):
    """(encrypted, algorithm) from the file header; never reads further."""
    with open(path, "rb") as f:
        head = f.read(512)
    if head.startswith(b"age-encryption.org/v1") or head.startswith(b"-----BEGIN AGE ENCRYPTED FILE"):
        return True, "age (X25519 + ChaCha20-Poly1305)"
    if head.startswith(b"-----BEGIN PGP MESSAGE"):
        return True, "OpenPGP (gpg)"
    if head[:1] and head[0] in (0x84, 0x85, 0x8C, 0xC1, 0xC3):
        return True, "OpenPGP (gpg)"
    if head.startswith(b"Salted__"):
        return True, "openssl enc (dérivation de clé à vérifier)"
    if head.startswith(b"PGDMP") or head.startswith(b"\x1f\x8b") or head.startswith(b"PK") \
            or head.startswith(b"\x28\xb5\x2f\xfd") or b"PostgreSQL database dump" in head \
            or head[257:262] == b"ustar" or head.lstrip().startswith(b"--") \
            or head.lstrip().startswith(b"CREATE") or head.lstrip().startswith(b"{"):
        return False, None
    return None, None


def tri(value):
    return {"yes": True, "no": False}.get(value)


def load_token(args):
    token = os.environ.get("CODEGATE_BACKUP_TOKEN", "")
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as f:
            token = f.read().strip()
    if not token.startswith("cg_bkp_"):
        sys.exit("CodeGate: token de sauvegarde manquant (--token-file ou CODEGATE_BACKUP_TOKEN).")
    return token


def post(args, path, payload):
    req = urllib.request.Request(
        args.url.rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "authorization": "Bearer " + load_token(args),
            "user-agent": "codegate-backup/" + VERSION,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            return json.loads(res.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        sys.exit(f"CodeGate: refusé ({e.code}) — {e.read().decode('utf-8', 'replace')[:200]}")
    except urllib.error.URLError as e:
        sys.exit(f"CodeGate: API injoignable ({e.reason}).")


# ── report ──

def cmd_report(args):
    payload = {
        "finishedAt": now_iso(),
        "status": args.status,
        "durationSeconds": args.duration,
        "inTransit": args.in_transit,
        "keyLocation": args.key_location,
        "signed": args.signed,
        "storageProvider": args.storage_provider,
        "storageLocation": args.storage_location,
        "immutable": tri(args.immutable),
        "versioning": tri(args.versioning),
        "separateAccount": tri(args.separate_account),
        "retentionDays": args.retention_days,
        "encrypted": False,
        "encryptionAlgorithm": None,
        "sha256": None,
        "sizeBytes": None,
    }
    if args.file:
        payload["sha256"] = sha256_of(args.file)
        payload["sizeBytes"] = os.path.getsize(args.file)
        encrypted, algorithm = detect_encryption(args.file)
        if encrypted is None:
            print("CodeGate: format non reconnu, chiffrement non détecté (précisez --encryption).",
                  file=sys.stderr)
        payload["encrypted"] = bool(encrypted)
        payload["encryptionAlgorithm"] = algorithm
    if args.encryption:
        payload["encrypted"] = args.encryption != "none"
        payload["encryptionAlgorithm"] = None if args.encryption == "none" else args.encryption
    res = post(args, "/api/v1/backups/agent/run", payload)
    print(f"CodeGate: exécution déclarée — score de récupération {res.get('score')}/100 "
          f"({res.get('status')}).")


# ── verify ──

def cmd_verify(args):
    res = post(args, "/api/v1/backups/agent/verify", {"sha256": sha256_of(args.file)})
    if res.get("integrityOk"):
        print("CodeGate: intégrité OK — la copie correspond à une sauvegarde enregistrée.")
    else:
        print("CodeGate: ALERTE — la copie ne correspond à aucune empreinte enregistrée.")
        sys.exit(3)


# ── restore-test ──

def docker(*cmd, **kw):
    return subprocess.run(["docker", *cmd], capture_output=True, text=True, check=False, **kw)


def prepare_dump(args, workdir):
    """Decrypt (optional) and decompress into a temp file; return its path."""
    current = args.file
    if args.decrypt_cmd:
        out = os.path.join(workdir, "decrypted")
        with open(current, "rb") as src, open(out, "wb") as dst:
            # One command and its arguments (`age -d -i key.txt`), no shell:
            # nothing in the value is interpreted (`;`, `$(…)`, redirections).
            try:
                r = subprocess.run(shlex.split(args.decrypt_cmd), stdin=src, stdout=dst,
                                   stderr=subprocess.PIPE, check=False)
            except (ValueError, OSError) as e:  # bad quoting, command not found
                raise RuntimeError("déchiffrement impossible : " + str(e)[:200]) from e
        if r.returncode != 0:
            raise RuntimeError("déchiffrement impossible : " + r.stderr.decode("utf-8", "replace")[:200])
        current = out
    with open(current, "rb") as f:
        magic = f.read(2)
    if magic == b"\x1f\x8b":
        out = os.path.join(workdir, "dump")
        with gzip.open(current, "rb") as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst)
        current = out
    return current


def restore_postgres(dump, name):
    with open(dump, "rb") as f:
        custom = f.read(5) == b"PGDMP"
    with open(dump, "rb") as f:
        if custom:
            cmd = ["exec", "-i", name, "pg_restore", "-U", "postgres", "-d", "restore",
                   "--no-owner", "--no-privileges"]
        else:
            cmd = ["exec", "-i", name, "psql", "-U", "postgres", "-d", "restore", "-q"]
        r = subprocess.run(["docker", *cmd], stdin=f, capture_output=True, check=False)
    errors = r.stderr.decode("utf-8", "replace").count("ERROR")
    tables = docker("exec", name, "psql", "-U", "postgres", "-d", "restore", "-At", "-c",
                    "select count(*) from information_schema.tables "
                    "where table_schema not in ('pg_catalog','information_schema') "
                    "and table_type = 'BASE TABLE'")
    records = docker("exec", name, "psql", "-U", "postgres", "-d", "restore", "-At", "-c",
                     "select coalesce(sum((xpath('/row/c/text()', query_to_xml(format("
                     "'select count(*) as c from %I.%I', schemaname, relname), false, true, '')))"
                     "[1]::text::bigint), 0) from pg_stat_user_tables")
    n_tables = int(tables.stdout.strip() or 0) if tables.returncode == 0 else 0
    n_records = int(records.stdout.strip() or 0) if records.returncode == 0 else 0
    return n_tables, n_records, errors


def cmd_restore_test(args):
    if not shutil.which("docker"):
        sys.exit("CodeGate: Docker est requis pour un test de restauration isolé.")
    started = time.time()
    started_iso = now_iso()
    name = "codegate-restore-" + secrets.token_hex(4)
    result, detail, n_tables, n_records = "failed", None, None, None
    with tempfile.TemporaryDirectory(prefix="codegate-restore-") as workdir:
        try:
            dump = prepare_dump(args, workdir)
            # Isolated: no network, random password, removed afterwards.
            r = docker("run", "-d", "--rm", "--name", name, "--network", "none",
                       "-e", "POSTGRES_PASSWORD=" + secrets.token_urlsafe(16),
                       "-e", "POSTGRES_DB=restore", args.image)
            if r.returncode != 0:
                raise RuntimeError("conteneur impossible à démarrer : " + r.stderr[:200])
            for _ in range(60):
                if docker("exec", name, "pg_isready", "-U", "postgres", "-d", "restore").returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("PostgreSQL n'a pas démarré")
            time.sleep(1)
            n_tables, n_records, errors = restore_postgres(dump, name)
            if n_tables > 0:
                result = "success"
                detail = f"{errors} erreur(s) non bloquante(s)" if errors else None
            else:
                detail = "aucune table restaurée"
        except RuntimeError as e:
            detail = str(e)
        finally:
            docker("rm", "-f", name)
    duration = int(time.time() - started)
    post(args, "/api/v1/backups/agent/restore-test", {
        "engine": "postgres",
        "startedAt": started_iso,
        "completedAt": now_iso(),
        "durationSeconds": duration,
        "result": result,
        "restoredTables": n_tables,
        "restoredRecords": n_records,
        "detail": detail,
    })
    if result == "success":
        print(f"CodeGate: restauration OK en {duration} s — {n_tables} tables, {n_records} lignes.")
    else:
        print(f"CodeGate: ÉCHEC de restauration — {detail}")
        sys.exit(3)


def main():
    p = argparse.ArgumentParser(description="CodeGate Backup Shield")
    p.add_argument("--url", default=os.environ.get("CODEGATE_URL", DEFAULT_URL))
    p.add_argument("--token-file")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("report", help="déclarer une exécution de sauvegarde")
    r.add_argument("--file", help="archive produite (hash + détection du chiffrement)")
    r.add_argument("--status", choices=["success", "failed"], default="success")
    r.add_argument("--duration", type=int, default=None, help="durée en secondes")
    r.add_argument("--encryption", help="forcer : none, ou nom de l'algorithme (ex. AES-256-GCM)")
    r.add_argument("--in-transit", choices=["tls1.3", "tls1.2", "ssh", "none", "unknown"], default="unknown")
    r.add_argument("--key-location", default="unknown",
                   choices=["external_kms", "secret_manager", "offline", "same_server", "unknown"])
    r.add_argument("--signed", action="store_true")
    r.add_argument("--storage-provider")
    r.add_argument("--storage-location", default="unknown",
                   choices=["offsite", "same_server", "local_disk", "unknown"])
    r.add_argument("--immutable", choices=["yes", "no", "unknown"], default="unknown")
    r.add_argument("--versioning", choices=["yes", "no", "unknown"], default="unknown")
    r.add_argument("--separate-account", choices=["yes", "no", "unknown"], default="unknown")
    r.add_argument("--retention-days", type=int)
    r.set_defaults(func=cmd_report)

    v = sub.add_parser("verify", help="revérifier une copie stockée")
    v.add_argument("--file", required=True)
    v.set_defaults(func=cmd_verify)

    t = sub.add_parser("restore-test", help="restauration isolée (PostgreSQL)")
    t.add_argument("--engine", choices=["postgres"], default="postgres")
    t.add_argument("--file", required=True, help="dump (.sql, .dump, .gz, chiffré avec --decrypt-cmd)")
    t.add_argument("--decrypt-cmd", help="commande de déchiffrement lisant stdin, ex. 'age -d -i key.txt'")
    t.add_argument("--image", default="postgres:17")
    t.set_defaults(func=cmd_restore_test)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
