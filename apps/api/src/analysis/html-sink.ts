/**
 * Where does the HTML written to innerHTML / dangerouslySetInnerHTML come
 * from? A regex on the sink line alone flags every assignment; in real audits
 * almost all of them render constant data, escaped values or the page's own
 * markup. This module looks at the right-hand side and at the file around it
 * and answers "provably no external input" — conservatively: anything it
 * cannot prove stays reported.
 */

/** Reads that bring data from outside the page's own code. */
const EXTERNAL_SOURCE =
  /\b(fetch|axios|XMLHttpRequest|WebSocket|EventSource)\b|\blocation\.(search|hash|href|pathname)|URLSearchParams|searchParams|useSearchParams|useParams|useLoaderData|localStorage|sessionStorage|document\.cookie|document\.referrer|window\.name|postMessage|addEventListener\(\s*['"]message|event\.data|\.value\b|\.files\b|FileReader|\breq\.|\brequest\.(body|query|params)|\$_(GET|POST|REQUEST)|\bprops\b/;

/** Calls that make a value safe for HTML. */
const ESCAPER = /^(?:[\w$]+\.)*(?:esc|escape\w*|escHtml|htmlEscape|encode\w*|sanitize\w*|purify|DOMPurify\.sanitize|xss|he\.encode)\s*\(/i;

/** Text written to the sink, or null when the line is not a sink. */
export function sinkExpression(line: string): string | null {
  const assign = /\.(?:inner|outer)HTML\s*=(?!=)\s*(.*)$/.exec(line);
  if (assign) return assign[1]!.replace(/\s*;?\s*\}?\s*\)?\s*;?\s*$/, "").trim();
  const prop = /__html\s*:\s*(.*?)\s*\}\s*\}?/.exec(line);
  if (prop) return prop[1]!.trim();
  return null;
}

/** Contents of each `${…}`, balanced on braces. */
function interpolations(expr: string): string[] {
  const out: string[] = [];
  for (let i = expr.indexOf("${"); i !== -1; i = expr.indexOf("${", i + 2)) {
    let depth = 1;
    let j = i + 2;
    for (; j < expr.length && depth; j++) {
      if (expr[j] === "{") depth++;
      else if (expr[j] === "}") depth--;
    }
    out.push(expr.slice(i + 2, j - 1).trim());
  }
  return out;
}

/** An interpolated expression that cannot carry markup from outside. */
function safeValue(e: string): boolean {
  if (ESCAPER.test(e)) return true;
  // Numbers: arithmetic, toFixed, Math.*, indexes.
  if (/^[\w$.\s()*+\-/%]*$/.test(e) && /(\d|toFixed|Math\.|\blength\b)/.test(e) && !/[a-z]\w*\s*$/i.test(e.replace(/\)\s*$/, ""))) {
    return true;
  }
  if (/^\(?[\w$.\s()*+\-/%]+\)?\.toFixed\(\d*\)$/.test(e)) return true;
  // A ternary between string literals.
  if (/^[^?]+\?\s*(['"`])[^'"`$]*\1\s*:\s*(['"`])[^'"`$]*\2$/.test(e)) return true;
  // Constant data: UPPER_CASE (possibly indexed), or a zero-argument helper call.
  if (/^(?:[\w$]+\.)*[A-Z][A-Z0-9_]+(\[[^\]]*\])?$/.test(e)) return true;
  if (/^[\w$]+\(\)$/.test(e)) return true;
  return false;
}

/**
 * Parameters of the named functions that enclose `position`: data a caller
 * (possibly external) controls. Callbacks (`.forEach((x) => …)`) are not
 * included — they iterate over values the function already has.
 */
function functionParams(fileText: string, position: number): Set<string> {
  const names = new Set<string>();
  const decl = /(?:\bfunction\s*[\w$]*\s*\(|(?:const|let|var)\s+[\w$]+\s*(?::[^=]+)?=\s*(?:async\s*)?\()([^)]*)\)/g;
  for (const m of fileText.matchAll(decl)) {
    const bodyStart = fileText.indexOf("{", m.index! + m[0].length);
    if (bodyStart === -1 || bodyStart > position) continue;
    // Arrow without braces (`= (x) => x.y`) ends at the line end.
    const between = fileText.slice(m.index! + m[0].length, bodyStart);
    let end: number;
    if (/=>\s*[^\s{]/.test(between)) {
      end = fileText.indexOf("\n", m.index!);
      if (end === -1) end = fileText.length;
    } else {
      let depth = 0;
      end = fileText.length;
      for (let k = bodyStart; k < fileText.length; k++) {
        if (fileText[k] === "{") depth++;
        else if (fileText[k] === "}" && --depth === 0) {
          end = k;
          break;
        }
      }
    }
    if (position < m.index! || position > end) continue;
    // Destructured names count too ({ body }); type annotations are dropped.
    const params = m[1]!.replace(/:\s*\{[^}]*\}/g, "").replace(/:\s*[\w$<>[\]|. ]+/g, "");
    for (const id of params.matchAll(/[A-Za-z_$][\w$]*/g)) names.add(id[0]);
  }
  return names;
}

const rootIdentifier = (expr: string) => /^\(?\s*(?:\.\.\.)?\[?\s*(?:\.\.\.)?([A-Za-z_$][\w$]*)/.exec(expr)?.[1];

/**
 * True when the sink on `line` provably writes no external input:
 * - literal markup, an UPPER_CASE constant, or a constant table lookup;
 * - `.map()` over constant arrays (`CARDS.map(…)`, `[...WORDS].map(…)`);
 * - templates whose every `${…}` is escaped, numeric, a literal choice,
 *   a constant or a zero-argument helper;
 * - the page's own text (`el.textContent` re-rendered) in a static HTML page;
 * - a file with no external input at all, when the value is not a parameter
 *   of a function (a caller could pass anything).
 */
export function htmlSinkIsSafe(line: string, fileText: string, file: string, completeFile = true): boolean {
  const expr = sinkExpression(line);
  if (expr === null) return false;
  if (expr === "") return false; // continues on the next line: can't prove anything
  // Literal markup or cleared element.
  if (/^(['"])(?:(?!\1)[^\\]|\\.)*\1$/.test(expr) || /^`[^`$]*`$/.test(expr)) return true;
  // Constant data and constant tables.
  if (/^(?:[\w$]+\.)*[A-Z][A-Z0-9_]+\b/.test(expr)) return true;
  if (/^\[\s*(?:\.\.\.)?(?:[\w$]+\.)*[A-Z][A-Z0-9_]+\b/.test(expr) && !/\.\.\.[a-z]/.test(expr)) return true;
  // Every interpolation proven safe, and nothing concatenated besides literals.
  const parts = interpolations(expr);
  if (parts.length && parts.every(safeValue)) {
    const outside = expr
      .replace(/`(?:[^`\\]|\\.)*`/g, "``")
      .replace(/\(\s*[^()?]+\?\s*(['"])[^'"]*\1\s*:\s*(['"])[^'"]*\2\s*\)/g, "''");
    if (!/\+\s*[A-Za-z_$]|[A-Za-z_$][\w$]*\s*\+/.test(outside.replace(/^[\w$.]+\.map\(/, ""))) return true;
  }
  // Re-rendering the page's own text in a static page.
  if (/\.html?$/i.test(file) && /^(?:[\w$]+\.)+textContent\b/.test(expr)) return true;
  // No external input anywhere in the file, and not a function parameter.
  // Only provable on a whole file: a diff shows a few lines, not the sources.
  // The variables written: the expression's root, or those of a template.
  const roots = expr.startsWith("`")
    ? interpolations(expr).map(rootIdentifier).filter((r): r is string => !!r)
    : [rootIdentifier(expr)].filter((r): r is string => !!r);
  const position = fileText.indexOf(line);
  if (completeFile && roots.length && position !== -1 && !EXTERNAL_SOURCE.test(fileText)) {
    const params = functionParams(fileText, position);
    if (roots.every((r) => !params.has(r))) return true;
  }
  return false;
}
