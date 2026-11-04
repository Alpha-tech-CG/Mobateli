/**
 * Minimal unified-diff parser. We only need the information the scanners act
 * on: which files changed, and the added lines with their new line numbers.
 * cahier §5.1 — analyse du diff complet.
 */

export interface AddedLine {
  file: string;
  line: number;
  content: string;
}

export interface ParsedDiff {
  files: string[];
  /** Whole files (repository scan), not a diff: context rules may look at the full file. */
  snapshot?: boolean;
  addedLines: AddedLine[];
  /** Added content per file, joined — convenient for structured parsing. */
  addedByFile: Map<string, string>;
  /**
   * New-side lines per file (added + context), in order, so a structured
   * scanner can tell which section an added line sits in. `hunkStart` marks
   * the first line of each hunk — structure is unknown across a gap.
   */
  newSideByFile: Map<string, NewSideLine[]>;
}

export interface NewSideLine {
  content: string;
  added: boolean;
  hunkStart: boolean;
}

const FILE_HEADER = /^\+\+\+ b\/(.+)$/;
const OLD_FILE_HEADER = /^--- /;
const HUNK_HEADER = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

export function parseUnifiedDiff(diff: string): ParsedDiff {
  const files: string[] = [];
  const addedLines: AddedLine[] = [];
  const addedByFile = new Map<string, string>();
  const newSideByFile = new Map<string, NewSideLine[]>();

  let currentFile: string | null = null;
  let newLineNo = 0;
  let hunkStart = false;
  const pushNewSide = (file: string, content: string, added: boolean) => {
    let list = newSideByFile.get(file);
    if (!list) newSideByFile.set(file, (list = []));
    list.push({ content, added, hunkStart });
    hunkStart = false;
  };

  for (const raw of diff.split("\n")) {
    const fileMatch = raw.match(FILE_HEADER);
    if (fileMatch) {
      const name = fileMatch[1]!.replace(/\r$/, "");
      currentFile = name === "dev/null" ? null : name;
      if (currentFile && !files.includes(currentFile)) files.push(currentFile);
      continue;
    }
    if (OLD_FILE_HEADER.test(raw) || raw.startsWith("diff ") || raw.startsWith("index ")) {
      continue;
    }
    const hunk = raw.match(HUNK_HEADER);
    if (hunk) {
      newLineNo = Number(hunk[1]);
      hunkStart = true;
      continue;
    }
    if (currentFile === null) continue;

    if (raw.startsWith("+")) {
      // Strip a trailing CR so content matches identically on Windows diffs.
      const content = raw.slice(1).replace(/\r$/, "");
      addedLines.push({ file: currentFile, line: newLineNo, content });
      addedByFile.set(currentFile, (addedByFile.get(currentFile) ?? "") + content + "\n");
      pushNewSide(currentFile, content, true);
      newLineNo++;
    } else if (raw.startsWith("-")) {
      // Removed line — does not advance the new-file counter.
    } else {
      // Context line.
      if (!raw.startsWith("\\")) pushNewSide(currentFile, raw.slice(1).replace(/\r$/, ""), false);
      newLineNo++;
    }
  }

  return { files, addedLines, addedByFile, newSideByFile };
}

/**
 * Whole-line comment in a common language (JS/TS, Python, shell, SQL, YAML…).
 * Scanners skip these to cut false positives: a rule example written in a
 * comment ("// never do: eval(x)") is not a vulnerability.
 */
export function isCommentLine(content: string): boolean {
  const t = content.trim();
  return (
    t.startsWith("//") ||
    t.startsWith("#") ||
    t.startsWith("*") ||
    t.startsWith("/*") ||
    t.startsWith("--") ||
    t.startsWith("<!--")
  );
}

/**
 * File paths where a "secret" or risky-looking snippet is expected and is not
 * a real exposure: tests, fixtures, mocks, examples and sample env files.
 */
export function isTestOrExampleFile(file: string): boolean {
  const f = file.toLowerCase();
  const base = f.split("/").pop() ?? f;
  return (
    /(^|\/)(tests?|__tests__|__mocks__|fixtures?|examples?|spec|e2e)(\/|$)/.test(f) ||
    /\.(test|spec|e2e|stories|fixture|mock|example|sample)\./.test(base) ||
    base.endsWith(".example") ||
    base.endsWith(".sample") ||
    base === ".env.example" ||
    base === ".env.sample" ||
    base === ".env.template"
  );
}
