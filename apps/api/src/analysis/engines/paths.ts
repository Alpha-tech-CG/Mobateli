import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { EngineFile } from "../rust-engine.js";

/** A diff path that stays inside a directory (no absolute path, no ".."). */
export function isSafeRelativePath(p: string): boolean {
  return (
    p.length > 0 &&
    !p.includes("\0") &&
    !/^([a-zA-Z]:)?[\\/]/.test(p) &&
    !p.split(/[\\/]/).includes("..")
  );
}

/** Write the PR's added code to a fresh temp dir; returns its path. */
export async function materializeFiles(files: EngineFile[]): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "codegate-semgrep-"));
  for (const f of files) {
    if (!isSafeRelativePath(f.path)) continue;
    const target = join(dir, f.path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, f.content, "utf8");
  }
  return dir;
}
