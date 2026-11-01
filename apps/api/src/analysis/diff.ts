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
  addedLines: AddedLine[];
  /** Added content per file, joined — convenient for structured parsing. */
  addedByFile: Map<string, string>;
}

const FILE_HEADER = /^\+\+\+ b\/(.+)$/;
const OLD_FILE_HEADER = /^--- /;
const HUNK_HEADER = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

export function parseUnifiedDiff(diff: string): ParsedDiff {
  const files: string[] = [];
  const addedLines: AddedLine[] = [];
  const addedByFile = new Map<string, string>();

  let currentFile: string | null = null;
  let newLineNo = 0;

  for (const raw of diff.split("\n")) {
    const fileMatch = raw.match(FILE_HEADER);
    if (fileMatch) {
      currentFile = fileMatch[1] === "dev/null" ? null : fileMatch[1]!;
      if (currentFile && !files.includes(currentFile)) files.push(currentFile);
      continue;
    }
    if (OLD_FILE_HEADER.test(raw) || raw.startsWith("diff ") || raw.startsWith("index ")) {
      continue;
    }
    const hunk = raw.match(HUNK_HEADER);
    if (hunk) {
      newLineNo = Number(hunk[1]);
      continue;
    }
    if (currentFile === null) continue;

    if (raw.startsWith("+")) {
      const content = raw.slice(1);
      addedLines.push({ file: currentFile, line: newLineNo, content });
      addedByFile.set(currentFile, (addedByFile.get(currentFile) ?? "") + content + "\n");
      newLineNo++;
    } else if (raw.startsWith("-")) {
      // Removed line — does not advance the new-file counter.
    } else {
      // Context line.
      newLineNo++;
    }
  }

  return { files, addedLines, addedByFile };
}
