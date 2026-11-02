"use client";

/**
 * Thin API client. Carries the JWT (stored in localStorage after login) as a
 * bearer token. All calls are client-side — the dashboard is a SPA shell over
 * the CodeGate API.
 */

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:4000";

const TOKEN_KEY = "codegate_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  try {
    window.localStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage unavailable — stay signed out */
  }
}

export function clearToken(): void {
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore */
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
  ) {
    super(code);
  }
}

/** Downloads the response as a file (POST with a body, or GET when body is null). */
export async function apiDownload(
  path: string,
  body: unknown,
  filename: string,
): Promise<void> {
  const token = getToken();
  const res = await fetch(`${API_URL}${path}`, {
    method: body === null ? "GET" : "POST",
    headers: {
      ...(body === null ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body === null ? {} : { body: JSON.stringify(body) }),
  });
  if (!res.ok) throw new ApiError(res.status, `http_${res.status}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      // Only declare JSON when there is a body: an empty JSON body is a 400.
      ...(init?.body !== undefined ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {}),
    },
  });

  if (!res.ok) {
    let code = `http_${res.status}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) code = body.error;
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, code);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** Claims of the current session (read-only, for UI hints — the API enforces). */
export function getSession(): { role?: string; mfa?: boolean; exp?: number } | null {
  const token = getToken();
  if (!token) return null;
  try {
    const payload = token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload)) as { role?: string; mfa?: boolean; exp?: number };
  } catch {
    return null;
  }
}
