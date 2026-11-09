/**
 * Pinned agent releases served from /agent/ (P2-5). The installer verifies
 * the SHA-256 before running anything; a test in apps/api fails when a file
 * changes without its checksum being updated here.
 */
export const AGENT_RELEASE = {
  version: "2.0.1",
  file: "codegate-agent.py",
  sha256: "fbf5f1a754fdb6b8957d5a83ebb4352972e4fd8cb882e3baa81aae706b000bb9",
} as const;

export const BACKUP_RELEASE = {
  version: "1.0.1",
  file: "codegate-backup.py",
  sha256: "35beae8ab4339dd998d0bba9c671a75f223cb8ee7ad49ab06ef08726d231af7c",
} as const;
