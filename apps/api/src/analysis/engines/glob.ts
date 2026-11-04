/**
 * Minimal path globs for `ignorePaths`: `**` (any depth, including none),
 * `*` (within one path segment), `?` (one character). Matched against the
 * repository-relative path with forward slashes. A pattern with no `/` matches
 * a file name at any depth (`*.min.js`), like .gitignore.
 */
export function globToRegExp(glob: string): RegExp {
  const pattern = glob.includes("/") ? glob : `**/${glob}`;
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        // "**/" = zero or more directories; a trailing "**" = anything.
        const slash = pattern[i + 2] === "/";
        re += slash ? "(?:.*/)?" : ".*";
        i += slash ? 2 : 1;
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${re}$`);
}

/** Builds a matcher for a list of globs (compiled once). */
export function pathMatcher(globs: string[]): (path: string) => boolean {
  if (!globs.length) return () => false;
  const res = globs.map(globToRegExp);
  return (path) => {
    const p = path.replace(/\\/g, "/").replace(/^\.\//, "");
    return res.some((r) => r.test(p));
  };
}
