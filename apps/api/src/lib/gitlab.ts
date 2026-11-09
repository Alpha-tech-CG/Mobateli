import { prisma } from "@codegate/db";
import { CODEGATE_COMMENT_MARKER } from "../analysis/explainer.js";
import { decrypt } from "./crypto.js";

/**
 * GitLab REST v4 client for merge request analysis (cahier §12.2 P3): read the
 * MR diff, then report back as a commit status + an MR note — the GitLab
 * equivalent of GitHub's check run and PR comment.
 */

export interface GitlabApi {
  request<T>(path: string, init?: RequestInit): Promise<T>;
  /** Binary GET (repository archives). */
  raw(path: string): Promise<Buffer>;
}

export function gitlabApi(baseUrl: string, token: string, fetchImpl: typeof fetch = fetch): GitlabApi {
  const root = baseUrl.replace(/\/+$/, "") + "/api/v4";
  return {
    async request<T>(path: string, init?: RequestInit): Promise<T> {
      const res = await fetchImpl(root + path, {
        ...init,
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
        headers: {
          "private-token": token,
          ...(init?.body ? { "content-type": "application/json" } : {}),
        },
      });
      if (!res.ok) throw new Error(`gitlab_${res.status}`);
      return (await res.json()) as T;
    },
    async raw(path: string): Promise<Buffer> {
      const res = await fetchImpl(root + path, {
        redirect: "follow",
        signal: AbortSignal.timeout(45_000),
        headers: { "private-token": token },
      });
      if (!res.ok) throw new Error(`gitlab_${res.status}`);
      return Buffer.from(await res.arrayBuffer());
    },
  };
}

/** API client for an organization's GitLab connection, or null without a token. */
export async function gitlabForOrg(organizationId: string, encryptionKey: string): Promise<GitlabApi | null> {
  const conn = await prisma.gitlabConnection.findUnique({
    where: { organizationId },
    select: { baseUrl: true, apiTokenEncrypted: true },
  });
  if (!conn?.apiTokenEncrypted) return null;
  return gitlabApi(conn.baseUrl, decrypt(conn.apiTokenEncrypted, encryptionKey));
}

interface MrDiff {
  old_path: string;
  new_path: string;
  diff: string;
  new_file: boolean;
  deleted_file: boolean;
}

/** Rebuild a unified diff (with file headers) from GitLab's per-file diffs. */
export async function fetchMrDiff(api: GitlabApi, projectId: string, iid: number): Promise<string> {
  const parts: string[] = [];
  for (let page = 1; page <= 20; page++) {
    const files = await api.request<MrDiff[]>(
      `/projects/${encodeURIComponent(projectId)}/merge_requests/${iid}/diffs?per_page=100&page=${page}`,
    );
    for (const f of files) {
      parts.push(
        `diff --git a/${f.old_path} b/${f.new_path}\n` +
          `--- ${f.new_file ? "/dev/null" : `a/${f.old_path}`}\n` +
          `+++ ${f.deleted_file ? "/dev/null" : `b/${f.new_path}`}\n` +
          f.diff,
      );
    }
    if (files.length < 100) break;
  }
  return parts.join("\n");
}

export type GitlabState = "success" | "failed" | "pending" | "running" | "canceled";

export async function setCommitStatus(
  api: GitlabApi,
  projectId: string,
  sha: string,
  state: GitlabState,
  description: string,
): Promise<void> {
  await api.request(`/projects/${encodeURIComponent(projectId)}/statuses/${sha}`, {
    method: "POST",
    body: JSON.stringify({ state, name: "CodeGate", description: description.slice(0, 255) }),
  });
}

/** Create or update CodeGate's single note on the MR. */
export async function upsertMrNote(api: GitlabApi, projectId: string, iid: number, body: string): Promise<void> {
  const base = `/projects/${encodeURIComponent(projectId)}/merge_requests/${iid}/notes`;
  const notes = await api.request<{ id: number; body: string }[]>(`${base}?per_page=100&sort=desc`);
  const mine = notes.find((n) => n.body.includes(CODEGATE_COMMENT_MARKER));
  if (mine) {
    await api.request(`${base}/${mine.id}`, { method: "PUT", body: JSON.stringify({ body }) });
  } else {
    await api.request(base, { method: "POST", body: JSON.stringify({ body }) });
  }
}
