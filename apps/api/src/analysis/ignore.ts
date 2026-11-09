/**
 * `.codegateignore` — paths the code analysis must skip (intentionally
 * vulnerable test corpora, vendored code, generated files…).
 *
 * Syntax: a subset of .gitignore —
 *  - one pattern per line; blank lines and `#` comments are ignored;
 *  - `*` matches within a path segment, `**` across segments, `?` one char;
 *  - a trailing `/` matches a directory and everything below it;
 *  - a pattern without `/` matches a file or directory name at any depth;
 *    a pattern containing `/` is anchored at the repository root;
 *  - `!pattern` re-includes a path excluded by an earlier pattern.
 *
 * Security: the file is read from the repository's default branch, never from
 * the pull request under analysis — otherwise a PR could exempt itself by
 * adding `**`. A PR that edits it is flagged as a sensitive-file change.
 * Secrets are scanned everywhere regardless: a credential committed under an
 * ignored path is leaked all the same.
 */

export const IGNORE_FILE = ".codegateignore";

interface Rule {
  negate: boolean;
  regex: RegExp;
}

function globToRegex(glob: string): string {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // `**/` → zero or more directories; trailing `**` → anything.
        if (glob[i + 2] === "/") {
          out += "(?:.*/)?";
          i += 2;
        } else {
          out += ".*";
          i += 1;
        }
      } else {
        out += "[^/]*";
      }
    } else if (c === "?") {
      out += "[^/]";
    } else {
      out += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return out;
}

function compile(line: string): Rule | null {
  let p = line.trim();
  if (!p || p.startsWith("#")) return null;
  const negate = p.startsWith("!");
  if (negate) p = p.slice(1);
  const dirOnly = p.endsWith("/");
  p = p.replace(/\/+$/, "");
  if (!p) return null;
  const anchored = p.includes("/");
  p = p.replace(/^\/+/, "");
  const body = globToRegex(p);
  // Match the path itself or anything below it (a directory pattern covers
  // its whole subtree). `dirOnly` patterns must have something below.
  const prefix = anchored ? "^" : "^(?:.*/)?";
  const suffix = dirOnly ? "/.*$" : "(?:/.*)?$";
  return { negate, regex: new RegExp(prefix + body + suffix) };
}

/** Build a predicate `isIgnored(path)` from the content of a .codegateignore. */
export function parseIgnoreFile(content: string): (path: string) => boolean {
  const rules = content
    .split(/\r?\n/)
    .map(compile)
    .filter((r): r is Rule => r !== null);
  if (!rules.length) return () => false;
  return (path: string) => {
    const p = path.replace(/\\/g, "/").replace(/^\.?\//, "");
    let ignored = false;
    for (const r of rules) if (r.regex.test(p)) ignored = !r.negate;
    return ignored;
  };
}

// The analysis pipeline applies the predicate (engines/pipeline.ts): every
// engine skips the ignored paths except the secret scanner.
