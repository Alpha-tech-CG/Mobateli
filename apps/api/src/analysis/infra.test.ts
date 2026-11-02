import { test } from "node:test";
import assert from "node:assert/strict";
import type { AgentReport } from "@codegate/shared";
import { evaluateInfra, isPublicBind } from "./infra.js";

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

test("public Postgres and Redis (Docker) ⇒ critical port findings", () => {
  const r = evaluateInfra({
    ...hardened,
    listening: [...hardened.listening, { proto: "tcp", address: "::", port: 5432, process: "postgres" }],
    docker: {
      containers: [
        { ...hardened.docker!.containers[0]!, name: "redis", publishedPorts: [{ hostIp: "", hostPort: 6379 }] },
      ],
    },
  });
  const ids = r.findings.map((f) => f.checkId);
  assert.ok(ids.includes("port.public.5432"));
  assert.ok(ids.includes("port.public.6379"));
  assert.ok(r.findings.every((f) => f.category !== "ports" || f.severity === "critical"));
  assert.equal(r.score, 50);
});

test("weak SSH + no firewall + no fail2ban ⇒ ssh, firewall and bruteforce findings", () => {
  const r = evaluateInfra({
    ...hardened,
    ssh: { permitRootLogin: "yes", passwordAuthentication: true, pubkeyAuthentication: true, maxAuthTries: 6 },
    firewall: { ufw: "inactive", nftablesRules: 0, iptablesRules: 0 },
    bruteforce: { fail2ban: false, crowdsec: false },
  });
  const ids = r.findings.map((f) => f.checkId).sort();
  assert.deepEqual(ids, [
    "bruteforce.ssh_unprotected",
    "firewall.inactive",
    "ssh.max_auth_tries",
    "ssh.password_auth",
    "ssh.root_login",
  ]);
});

test("unknown firewall (not root) is info, never reported as safe or inactive", () => {
  const r = evaluateInfra({
    ...hardened,
    firewall: { ufw: null, nftablesRules: null, iptablesRules: null },
  });
  assert.deepEqual(r.findings.map((f) => [f.checkId, f.severity]), [["firewall.unknown", "info"]]);
});

test("privileged container with docker.sock ⇒ critical docker findings", () => {
  const r = evaluateInfra({
    ...hardened,
    docker: {
      containers: [
        {
          ...hardened.docker!.containers[0]!,
          name: "ci",
          user: "",
          privileged: true,
          dockerSocketMounted: true,
          capAdd: ["SYS_ADMIN"],
          memoryLimit: 0,
        },
      ],
    },
  });
  const sev = Object.fromEntries(r.findings.map((f) => [f.checkId, f.severity]));
  assert.equal(sev["docker.socket.ci"], "critical");
  assert.equal(sev["docker.privileged.ci"], "critical");
  assert.equal(sev["docker.caps.ci"], "high");
  assert.equal(sev["docker.root.ci"], "medium");
  assert.equal(sev["docker.limits.ci"], "low");
  assert.equal(r.score, 30);
});

test("pending security updates scale severity; score floors at 0", () => {
  const many = evaluateInfra({ ...hardened, updates: { manager: "apt", pendingSecurity: 12, autoUpdates: false } });
  assert.equal(many.findings.find((f) => f.checkId === "updates.security_pending")?.severity, "high");
  const worst = evaluateInfra({
    ...hardened,
    listening: [2375, 3306, 5432, 6379, 27017].map((port) => ({
      proto: "tcp" as const, address: "0.0.0.0", port, process: null,
    })),
  });
  assert.equal(worst.score, 0);
});

test("database without any scheduled backup ⇒ high backups finding", () => {
  const withDb = { ...hardened, backups: { jobs: 0, tools: [], codegateReporting: false } };
  assert.equal(evaluateInfra(withDb).findings[0]?.checkId, "backups.none");
  const monitored = { ...hardened, backups: { jobs: 1, tools: ["codegate-backup", "pg_dump"], codegateReporting: true } };
  assert.deepEqual(evaluateInfra(monitored).findings, []);
  const unmonitored = { ...hardened, backups: { jobs: 1, tools: ["restic"], codegateReporting: false } };
  assert.equal(evaluateInfra(unmonitored).findings[0]?.severity, "low");
});
