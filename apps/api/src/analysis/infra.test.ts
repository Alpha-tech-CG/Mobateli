import { test } from "node:test";
import assert from "node:assert/strict";
import type { AgentReport } from "@codegate/shared";
import { evaluateInfra, imageName, isPublicBind, scoreOf } from "./infra.js";

const hardened: AgentReport = {
  agentVersion: "1.0.0",
  hostname: "vps-1",
  os: "Ubuntu 24.04",
  listening: [
    { proto: "tcp", address: "0.0.0.0", port: 22, process: "sshd" },
    { proto: "tcp", address: "0.0.0.0", port: 443, process: "nginx" },
    { proto: "tcp", address: "127.0.0.1", port: 5432, process: "postgres" },
  ],
  ssh: {
    permitRootLogin: "no",
    passwordAuthentication: false,
    pubkeyAuthentication: true,
    maxAuthTries: 3,
  },
  firewall: { ufw: "active", nftablesRules: null, iptablesRules: null },
  bruteforce: { fail2ban: true, crowdsec: false },
  docker: {
    containers: [
      {
        name: "api",
        image: "app:1",
        user: "1000",
        privileged: false,
        dockerSocketMounted: false,
        capAdd: [],
        publishedPorts: [{ hostIp: "127.0.0.1", hostPort: 4000 }],
        readOnlyRootfs: true,
        memoryLimit: 512 * 1024 * 1024,
      },
    ],
  },
  updates: { manager: "apt", pendingSecurity: 0, autoUpdates: true },
};

test("hardened server ⇒ score 100, no findings", () => {
  const r = evaluateInfra(hardened);
  assert.deepEqual(r.findings, []);
  assert.equal(r.score, 100);
});

test("loopback binds are not public", () => {
  assert.equal(isPublicBind("127.0.0.1"), false);
  assert.equal(isPublicBind("[::1]"), false);
  assert.equal(isPublicBind("0.0.0.0"), true);
  assert.equal(isPublicBind("*"), true);
});

const base = hardened.docker!.containers[0]!;
const ids = (r: { findings: { checkId: string }[] }) => r.findings.map((f) => f.checkId);
const sevOf = (r: { findings: { checkId: string; severity: string }[] }) =>
  Object.fromEntries(r.findings.map((f) => [f.checkId, f.severity]));

test("public Postgres and Redis (Docker) ⇒ critical port findings", () => {
  const r = evaluateInfra({
    ...hardened,
    listening: [...hardened.listening, { proto: "tcp", address: "::", port: 5432, process: "postgres" }],
    docker: { containers: [{ ...base, name: "redis", publishedPorts: [{ hostIp: "", hostPort: 6379 }] }] },
  });
  assert.ok(ids(r).includes("port.public.5432"));
  assert.ok(ids(r).includes("port.public.6379"));
  assert.ok(r.findings.every((f) => f.category !== "ports" || f.severity === "critical"));
  assert.equal(r.score, scoreOf(r.findings));
});

test("weak SSH + no firewall + no fail2ban ⇒ findings and an SSH brute-force chain", () => {
  const r = evaluateInfra({
    ...hardened,
    ssh: { permitRootLogin: "yes", passwordAuthentication: true, pubkeyAuthentication: true, maxAuthTries: 6 },
    firewall: { ufw: "inactive", nftablesRules: 0, iptablesRules: 0 },
    bruteforce: { fail2ban: false, crowdsec: false },
  });
  assert.deepEqual(ids(r).sort(), [
    "bruteforce.ssh_unprotected",
    "firewall.inactive",
    "ssh.max_auth_tries",
    "ssh.password_auth",
    "ssh.root_login",
  ]);
  assert.equal(r.chains.find((c) => c.id === "chain.ssh_bruteforce")?.severity, "critical");
  assert.ok(r.findings.every((f) => f.verifyCommand), "every SSH/firewall finding has a verification command");
});

test("unknown firewall (not root) is info, never reported as safe or inactive", () => {
  const r = evaluateInfra({ ...hardened, firewall: { ufw: null, nftablesRules: null, iptablesRules: null } });
  assert.deepEqual(r.findings.map((f) => [f.checkId, f.severity]), [["firewall.unknown", "info"]]);
});

test("P0-1: privileged cAdvisor mounting / and /var/lib/docker ⇒ critical with the host paths as proof", () => {
  const r = evaluateInfra({
    ...hardened,
    docker: {
      containers: [
        {
          ...base,
          name: "cadvisor",
          image: "gcr.io/cadvisor/cadvisor:v0.49.1",
          user: "",
          privileged: true,
          mounts: [
            { source: "/", destination: "/rootfs", rw: false },
            { source: "/var/lib/docker", destination: "/var/lib/docker", rw: false },
            { source: "/sys", destination: "/sys", rw: false },
          ],
          effectiveUid: 0,
        },
      ],
    },
  });
  const f = r.findings.find((x) => x.checkId === "docker.privileged.cadvisor")!;
  assert.equal(f.severity, "critical");
  assert.match(f.evidence!, /\/ -> \/rootfs \(ro\)/);
  assert.match(f.evidence!, /\/var\/lib\/docker/);
  assert.match(f.recommendation, /devices: \[\/dev\/kmsg\]/, "image-aware fix for cAdvisor");
  assert.ok(!ids(r).includes("docker.root.cadvisor"), "privileged already covers root");
});

test("P0-1: sensitive host mounts and escape capabilities without privileged", () => {
  const r = evaluateInfra({
    ...hardened,
    docker: {
      containers: [
        { ...base, name: "backup", mounts: [{ source: "/etc", destination: "/host-etc", rw: true }] },
        { ...base, name: "net", capAdd: ["CAP_SYS_ADMIN", "NET_ADMIN"] },
        { ...base, name: "tz", mounts: [{ source: "/etc/localtime", destination: "/etc/localtime", rw: false }] },
      ],
    },
  });
  const sev = sevOf(r);
  assert.equal(sev["docker.host_mount.backup"], "critical");
  assert.equal(sev["docker.caps.net"], "critical");
  assert.equal(sev["docker.host_mount.tz"], undefined, "/etc/localtime is harmless");
});

test("P0-3: a read-only socket proxy is a mitigation and lowers the score", () => {
  const direct = {
    ...base,
    name: "traefik",
    image: "traefik:v3.1",
    dockerSocketMounted: true,
    mounts: [{ source: "/var/run/docker.sock", destination: "/var/run/docker.sock", rw: false }],
  };
  const before = evaluateInfra({ ...hardened, docker: { containers: [direct] } });
  assert.equal(sevOf(before)["docker.socket.traefik"], "critical");
  assert.match(before.findings[0]!.detail, /ne protège pas/, "P1-1: :ro is called out as insufficient");

  const after = evaluateInfra({
    ...hardened,
    docker: {
      containers: [
        { ...direct, dockerSocketMounted: false, mounts: [] },
        {
          ...base,
          name: "socket-proxy",
          image: "tecnativa/docker-socket-proxy:0.2",
          dockerSocketMounted: true,
          mounts: [{ source: "/var/run/docker.sock", destination: "/var/run/docker.sock", rw: false }],
          socketProxyPost: false,
        },
      ],
    },
  });
  assert.equal(after.findings.filter((f) => f.severity === "critical").length, 0);
  assert.ok(after.mitigations.some((m) => /socket-proxy/.test(m)));
  assert.ok(after.score > before.score, "hardening must raise the score");

  const writable = evaluateInfra({
    ...hardened,
    docker: { containers: [{ ...base, name: "sp", image: "tecnativa/docker-socket-proxy", dockerSocketMounted: true, socketProxyPost: true }] },
  });
  assert.equal(sevOf(writable)["docker.socket_proxy_write.sp"], "high");
});

test("P0-4: root is judged on the effective UID, with image-aware advice", () => {
  const r = evaluateInfra({
    ...hardened,
    docker: {
      containers: [
        { ...base, name: "alpha-postgres", image: "postgres:16", user: "", effectiveUid: 999 },
        { ...base, name: "alpha-redis", image: "redis:7-alpine", user: "" }, // old agent: no UID measured
        { ...base, name: "portal", image: "ghcr.io/acme/portal:1", user: "", effectiveUid: 0, publishedPorts: [{ hostIp: "0.0.0.0", hostPort: 3000 }] },
        { ...base, name: "worker", image: "acme/worker:1", user: "", effectiveUid: 0 },
      ],
    },
  });
  const sev = sevOf(r);
  assert.equal(sev["docker.root.alpha-postgres"], undefined);
  assert.equal(sev["docker.root.alpha-redis"], undefined);
  assert.equal(sev["docker.root.portal"], "medium", "P1-8: public service weighs more");
  assert.equal(sev["docker.root.worker"], "low", "internal service weighs less");
  assert.ok(r.mitigations.some((m) => m.includes("alpha-postgres")));
  assert.match(r.findings.find((f) => f.checkId === "docker.root.worker")!.recommendation, /chown/);
});

test("P0-2: TLS is judged per hostname with SNI; the default certificate is not a finding", () => {
  const r = evaluateInfra({
    ...hardened,
    tls: [
      { port: 443, protocol: "TLSv1.3", legacyAccepted: false, certExpiresInDays: 3650, selfSigned: true },
      { port: 443, protocol: "TLSv1.3", legacyAccepted: false, certExpiresInDays: 70, selfSigned: false, sni: "app.sslip.io", trusted: true, issuer: "Let's Encrypt" },
    ],
  });
  assert.deepEqual(r.findings, []);
  assert.ok(r.mitigations.some((m) => m.includes("app.sslip.io")));

  const bad = evaluateInfra({
    ...hardened,
    tls: [
      { port: 443, protocol: "TLSv1.3", legacyAccepted: true, certExpiresInDays: 9, selfSigned: false, sni: "a.example", trusted: true },
      { port: 8443, protocol: "TLSv1.2", legacyAccepted: false, certExpiresInDays: -2, selfSigned: true, sni: "b.example", trusted: false },
    ],
  });
  const sev = sevOf(bad);
  assert.equal(sev["tls.cert_expiry.443.a.example"], "high");
  assert.equal(sev["tls.legacy_accepted.443"], "medium");
  assert.equal(sev["tls.cert_expiry.8443.b.example"], "critical");
  assert.equal(sev["tls.untrusted.8443.b.example"], "medium");

  const noSni = evaluateInfra({ ...hardened, tls: [{ port: 443, protocol: "TLSv1.3", legacyAccepted: false, certExpiresInDays: 80, selfSigned: true }] });
  assert.deepEqual(noSni.findings.map((f) => [f.checkId, f.severity]), [["tls.default_cert.443", "info"]]);
});

test("P0-5: the score is continuous — every fix moves it, never stuck at 0", () => {
  const worst = evaluateInfra({
    ...hardened,
    listening: [2375, 3306, 5432, 6379, 27017].map((port) => ({ proto: "tcp" as const, address: "0.0.0.0", port, process: null })),
  });
  assert.ok(worst.score > 0);
  const fixedOne = evaluateInfra({
    ...hardened,
    listening: [3306, 5432, 6379, 27017].map((port) => ({ proto: "tcp" as const, address: "0.0.0.0", port, process: null })),
  });
  assert.ok(fixedOne.score > worst.score);
  const many = evaluateInfra({ ...hardened, updates: { manager: "apt", pendingSecurity: 12, autoUpdates: false } });
  assert.equal(many.findings.find((f) => f.checkId === "updates.security_pending")?.severity, "high");
});

test("P1-9: an accepted risk leaves the score but stays listed", () => {
  const report = { ...hardened, firewall: { ufw: "inactive" as const, nftablesRules: 0, iptablesRules: 0 } };
  const open = evaluateInfra(report);
  const accepted = evaluateInfra(report, { accepted: new Set(["firewall.inactive"]) });
  assert.equal(accepted.score, 100);
  assert.ok(open.score < 100);
  assert.ok(ids(accepted).includes("firewall.inactive"));
});

test("P1-3 / P2-3: exposed admin console + privileged container on the same network ⇒ attack chain", () => {
  const r = evaluateInfra({
    ...hardened,
    docker: {
      containers: [
        { ...base, name: "grafana", image: "grafana/grafana:11", routedHosts: ["grafana.example"], networks: ["monitoring"] },
        { ...base, name: "prom", image: "prom/prometheus", routedHosts: ["prom.example"], networks: ["monitoring"], routeAuth: "none" },
        { ...base, name: "cadvisor", image: "gcr.io/cadvisor/cadvisor", privileged: true, networks: ["monitoring"] },
        { ...base, name: "dash", image: "traefik:v3", routedHosts: ["traefik.example"], routeAuth: "broken" },
      ],
    },
  });
  const sev = sevOf(r);
  assert.equal(sev["admin.exposed.grafana"], "low", "Grafana has its own login");
  assert.equal(sev["admin.exposed.prom"], "high", "Prometheus has none");
  assert.equal(sev["admin.auth_broken.dash"], "high");
  const chain = r.chains.find((c) => c.id === "chain.admin_pivot.prom.cadvisor");
  assert.equal(chain?.severity, "critical");
  assert.ok(chain!.checkIds.includes("docker.privileged.cadvisor"));
});

test("P1-4 / P1-5 / P1-6 / P1-7: secrets, UFW bypass, headers, daemon", () => {
  const r = evaluateInfra({
    ...hardened,
    firewall: { ufw: "active", ufwAllowed: [22, 80, 443], nftablesRules: null, iptablesRules: null },
    docker: {
      containers: [
        { ...base, name: "api", publishedPorts: [{ hostIp: "0.0.0.0", hostPort: 3000 }], secretEnvNames: ["JWT_SECRET"] },
        { ...base, name: "host", networkMode: "host" },
      ],
      daemon: { usernsRemap: false, liveRestore: false, noNewPrivileges: false, logMaxSize: false },
      envFiles: [{ path: "/srv/app/.env", mode: "644", worldReadable: true }],
    },
    tls: [
      {
        port: 443, protocol: "TLSv1.3", legacyAccepted: false, certExpiresInDays: 60, selfSigned: false,
        sni: "app.example", trusted: true, headers: { hsts: false, csp: false, frameOptions: true, contentTypeOptions: true },
      },
    ],
  });
  const sev = sevOf(r);
  assert.equal(sev["secrets.env.api"], "medium");
  assert.equal(sev["secrets.env_file./srv/app/.env"], "medium");
  assert.equal(sev["firewall.docker_bypass.3000"], "medium");
  assert.equal(sev["http.headers.app.example"], "medium");
  assert.equal(sev["daemon.hardening"], "medium");
  assert.equal(sev["network.host_mode.host"], "high");
  assert.match(r.findings.find((f) => f.checkId === "secrets.env.api")!.evidence!, /JWT_SECRET/);
});

test("database without any scheduled backup ⇒ high backups finding", () => {
  const withDb = { ...hardened, backups: { jobs: 0, tools: [], codegateReporting: false } };
  assert.equal(evaluateInfra(withDb).findings[0]?.checkId, "backups.none");
  const monitored = { ...hardened, backups: { jobs: 1, tools: ["codegate-backup", "pg_dump"], codegateReporting: true } };
  assert.deepEqual(evaluateInfra(monitored).findings, []);
  const unmonitored = { ...hardened, backups: { jobs: 1, tools: ["restic"], codegateReporting: false } };
  assert.equal(evaluateInfra(unmonitored).findings[0]?.severity, "low");
});

test("imageName strips registry, tag and digest", () => {
  assert.equal(imageName("gcr.io/cadvisor/cadvisor:v0.49.1"), "cadvisor/cadvisor");
  assert.equal(imageName("tecnativa/docker-socket-proxy@sha256:abc"), "tecnativa/docker-socket-proxy");
  assert.equal(imageName("postgres:16"), "postgres");
  assert.equal(imageName("localhost:5000/team/app:1"), "team/app");
});

test("P1-7: extra UID-0 account, passwordless sudo, auto-updates that stopped running", () => {
  const r = evaluateInfra({
    ...hardened,
    updates: { manager: "apt", pendingSecurity: 0, autoUpdates: true, autoUpdatesLastRunDays: 40 },
    host: { uid0Accounts: ["root", "toor"], passwordlessSudo: ["deploy"] },
  });
  const sev = sevOf(r);
  assert.equal(sev["host.uid0_accounts"], "critical");
  assert.equal(sev["host.sudo_nopasswd"], "medium");
  assert.equal(sev["updates.auto_stale"], "medium");
  const clean = evaluateInfra({ ...hardened, host: { uid0Accounts: ["root"], passwordlessSudo: [] } });
  assert.deepEqual(clean.findings, []);
});
