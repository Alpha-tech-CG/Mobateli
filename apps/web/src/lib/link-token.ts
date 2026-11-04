"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Read the one-time token of an email link. It travels in the URL fragment
 * (`#token=…`), which browsers never send to a server; we remove it from the
 * address bar right away so it doesn't linger in history or screenshots.
 * `undefined` while reading, `null` when absent.
 *
 * The fragment is read once per mount: effects may run twice (React strict
 * mode), and the second run would otherwise find the hash already cleared.
 */
export function useLinkToken(): string | null | undefined {
  const read = useRef<string | null | undefined>(undefined);
  const [token, setToken] = useState<string | null | undefined>(undefined);
  useEffect(() => {
    if (read.current === undefined) {
      const value = new URLSearchParams(window.location.hash.slice(1)).get("token");
      read.current = value && /^[A-Za-z0-9_-]{20,100}$/.test(value) ? value : null;
      if (window.location.hash) {
        window.history.replaceState(null, "", window.location.pathname + window.location.search);
      }
    }
    setToken(read.current);
  }, []);
  return token;
}
