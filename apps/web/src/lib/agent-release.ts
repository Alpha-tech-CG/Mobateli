/**
 * Pinned agent releases served from /agent/ (P2-5). The installer verifies
 * the SHA-256 before running anything; a test in apps/api fails when a file
 * changes without its checksum being updated here.
 */
export const AGENT_RELEASE = {
  version: "2.0.0",
  file: "codegate-agent.py",
  sha256: "5a4c33ed7b6d7fd81cdc8574c7f32fedfb6a4d65c3486a94249752389ab00174",
} as const;

export const BACKUP_RELEASE = {
  version: "1.0.0",
  file: "codegate-backup.py",
  sha256: "22df8184652f30163d8732859f1b61f1ac798e3a92ef1642a4ca43d5c3484275",
} as const;
