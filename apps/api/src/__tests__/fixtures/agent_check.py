"""Offline checks of the agent's parsing helpers (no system access needed)."""
import importlib.util
import re
import sys
import warnings

path = sys.argv[1]
spec = importlib.util.spec_from_file_location("agent", path)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

assert a._secret_env_names([
    "POSTGRES_PASSWORD=s3cr3t", "POSTGRES_PASSWORD_FILE=/run/secrets/x", "JWT_SECRET=",
    "API_KEY=abc", "PATH=/usr/bin", "REDIS_PASSWORD=changeme",
]) == ["API_KEY", "POSTGRES_PASSWORD"]

labels = {
    "traefik.http.routers.g.rule": "Host(`grafana.ex.com`) || Host(`g2.ex.com`)",
    "traefik.http.routers.g.middlewares": "auth",
    "traefik.http.middlewares.auth.basicauth.usersfile": "/etc/traefik/.htpasswd",
}
proxy = {"Mounts": [{"Destination": "/etc/traefik", "Source": "/nonexistent/traefik"}]}
assert a._route_facts({}, labels, proxy, {}) == (["g2.ex.com", "grafana.ex.com"], "broken")
assert a._route_facts({}, {"traefik.http.routers.p.rule": "Host(`p.ex.com`)"}, None, {}) == (["p.ex.com"], "none")
fa = {"traefik.http.routers.p.rule": "Host(`p.ex.com`)", "traefik.http.routers.p.middlewares": "sso",
      "traefik.http.middlewares.sso.forwardauth.address": "http://auth:4181"}
assert a._route_facts({}, fa, None, {}) == (["p.ex.com"], "ok")

yaml = "http:\n  middlewares:\n    admin-auth:\n      basicAuth:\n        usersFile: /etc/traefik/users.htpasswd\n"
toml = '[http.middlewares.ops.basicAuth]\n  usersFile = "/etc/traefik/ops.htpasswd"\n'
found = {}
for p in a.FILE_PROVIDER_USERS:
    for m in p.finditer(yaml + toml):
        found[m.group(1)] = m.group(2).strip()
assert found == {"admin-auth": "/etc/traefik/users.htpasswd", "ops": "/etc/traefik/ops.htpasswd"}, found

assert a._host_path({"Mounts": [{"Destination": "/etc/traefik", "Source": "/srv/traefik"}]}, "/etc/traefik/x/.htpasswd") == "/srv/traefik/x/.htpasswd"

warnings.simplefilter("error")  # P2-4: no DeprecationWarning
assert len(a._legacy_versions()) == 2
a._probe_tls(9, a._legacy_versions()[0])  # nothing listens on 9: returns None, must not warn
print("agent helpers ok")
