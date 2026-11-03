import { gunzipSync } from "node:zlib";

/**
 * Read a repository snapshot (tar.gz from GitHub or GitLab) in memory and keep
 * only the files worth analysing. Nothing is written to disk and the code is
 * never persisted — only findings are (cahier §11.2).
 */

export interface RepoFile {
  path: string;
  content: string;
}

export interface ExtractLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
}

export const DEFAULT_LIMITS: ExtractLimits = {
  maxFiles: 4000,
  maxFileBytes: 512 * 1024,
  maxTotalBytes: 40 * 1024 * 1024,
};

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "out", ".next", ".nuxt", "vendor", "target",
  "coverage", "__pycache__", ".venv", "venv", ".turbo", ".cache", ".vercel", ".vercel-deploy",
]);
const SKIP_FILES = new Set([
  "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "Cargo.lock",
  "poetry.lock", "Pipfile.lock", "go.sum", "composer.lock", "Gemfile.lock",
]);
const BINARY_EXT =
  /\.(png|jpe?g|gif|webp|ico|svgz|bmp|tiff?|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|wasm|so|dylib|dll|exe|bin|o|a|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|ogg|wav|flac|psd|sqlite|db)$/i;

export function shouldKeep(path: string): boolean {
  const parts = path.split("/");
  if (parts.some((p) => SKIP_DIRS.has(p))) return false;
  const base = parts[parts.length - 1]!;
  if (SKIP_FILES.has(base)) return false;
  if (BINARY_EXT.test(base)) return false;
  if (/\.min\.(js|css)$/.test(base)) return false;
  return true;
}

function cString(buf: Buffer, start: number, len: number): string {
  const slice = buf.subarray(start, start + len);
  const nul = slice.indexOf(0);
  return slice.subarray(0, nul === -1 ? slice.length : nul).toString("utf8");
}

/** Parse pax extended header records ("<len> key=value\n"). */
function paxPath(data: Buffer): string | null {
  let i = 0;
  const text = data.toString("utf8");
  while (i < text.length) {
    const sp = text.indexOf(" ", i);
    if (sp === -1) break;
    const len = Number(text.slice(i, sp));
    if (!Number.isFinite(len) || len <= 0) break;
    const record = text.slice(sp + 1, i + len - 1);
    if (record.startsWith("path=")) return record.slice(5);
    i += len;
  }
  return null;
}

/**
 * Extract text files from a gzipped tarball (ustar + pax). The archive's top
 * folder (`owner-repo-sha/`) is stripped from paths.
 */
export function extractTarGz(archive: Buffer, limits: ExtractLimits = DEFAULT_LIMITS): {
  files: RepoFile[];
  skipped: number;
  truncated: boolean;
} {
  const tar = gunzipSync(archive, { maxOutputLength: limits.maxTotalBytes * 4 });
  const files: RepoFile[] = [];
  let skipped = 0;
  let total = 0;
  let truncated = false;
  let nextPath: string | null = null;
  let offset = 0;

  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break; // end-of-archive marker
    const name = cString(header, 0, 100);
    const prefix = cString(header, 345, 155);
    const size = parseInt(cString(header, 124, 12).trim() || "0", 8);
    const type = String.fromCharCode(header[156] || 48);
    const dataStart = offset + 512;
    const data = tar.subarray(dataStart, dataStart + size);
    offset = dataStart + Math.ceil(size / 512) * 512;

    if (type === "x") {
      nextPath = paxPath(data);
      continue;
    }
    if (type === "g" || type === "L") {
      if (type === "L") nextPath = cString(data, 0, data.length);
      continue;
    }
    const fullPath = nextPath ?? (prefix ? `${prefix}/${name}` : name);
    nextPath = null;
    if (type !== "0" && type !== "\0" && type !== "7") continue; // dirs, links…

    const path = fullPath.split("/").slice(1).join("/"); // drop top folder
    if (!path || !shouldKeep(path)) {
      skipped++;
      continue;
    }
    if (size > limits.maxFileBytes || data.subarray(0, 8000).includes(0)) {
      skipped++; // too large or binary
      continue;
    }
    if (files.length >= limits.maxFiles || total + size > limits.maxTotalBytes) {
      truncated = true;
      break;
    }
    total += size;
    files.push({ path, content: data.toString("utf8") });
  }
  return { files, skipped, truncated };
}
