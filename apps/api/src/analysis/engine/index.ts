import { readFileSync } from "node:fs";
import type { AddedLine } from "../diff.js";
import type { FindingResult, SecretResult } from "../types.js";

/**
 * Loader for the Rust scan engine (services/scan-engine, cahier §9.3),
 * compiled to WebAssembly and run in-process. Returns null when the module is
 * missing, fails to load, or is disabled (CODEGATE_SCAN_ENGINE=off): the
 * TypeScript rules then do the whole analysis.
 */

export interface EngineOutput {
  engine: string;
  version: string;
  secrets: SecretResult[];
  findings: (FindingResult & { filePath: string; line: number; ruleId: string })[];
  /** Files whose added code was analysed on the syntax tree. */
  astFiles: string[];
}

// Minimal WebAssembly typings (the API's tsconfig has no DOM lib).
interface WasmRuntime {
  Module: new (bytes: Uint8Array) => object;
  Instance: new (module: object, imports: object) => { exports: unknown };
}
const WebAssemblyRuntime = (globalThis as unknown as { WebAssembly: WasmRuntime }).WebAssembly;

interface Exports {
  memory: { buffer: ArrayBuffer };
  cg_alloc(len: number): number;
  cg_free(ptr: number, len: number): void;
  cg_scan(ptr: number, len: number): bigint;
}

let exportsCache: Exports | null | undefined;

function load(): Exports | null {
  if (exportsCache !== undefined) return exportsCache;
  exportsCache = null;
  if (process.env.CODEGATE_SCAN_ENGINE === "off") return null;
  try {
    const bytes = readFileSync(new URL("./codegate_scan.wasm", import.meta.url));
    const instance = new WebAssemblyRuntime.Instance(new WebAssemblyRuntime.Module(bytes), {});
    exportsCache = instance.exports as unknown as Exports;
  } catch {
    exportsCache = null;
  }
  return exportsCache;
}

export function engineAvailable(): boolean {
  return load() !== null;
}

/** Run the Rust engine on the PR's added lines, or null to fall back. */
export function scanWithEngine(lines: AddedLine[]): EngineOutput | null {
  const wasm = load();
  if (!wasm) return null;
  try {
    const input = new TextEncoder().encode(JSON.stringify({ lines }));
    const inPtr = wasm.cg_alloc(input.length);
    new Uint8Array(wasm.memory.buffer, inPtr, input.length).set(input);
    const packed = wasm.cg_scan(inPtr, input.length);
    wasm.cg_free(inPtr, input.length);

    const outPtr = Number(packed >> 32n);
    const outLen = Number(packed & 0xffffffffn);
    // Read after the call: the memory may have grown (new buffer).
    const json = new TextDecoder().decode(new Uint8Array(wasm.memory.buffer, outPtr, outLen));
    wasm.cg_free(outPtr, outLen);

    const parsed = JSON.parse(json) as EngineOutput | { error: string };
    return "error" in parsed ? null : parsed;
  } catch {
    return null;
  }
}
