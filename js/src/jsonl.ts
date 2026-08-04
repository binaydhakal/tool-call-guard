/**
 * JSONL audit sink for Node — one line per audit event, append-only.
 * Lives in its own entry point ("tool-call-guard/jsonl") so the core stays
 * runtime-agnostic (browsers, edge, workers never import node:fs).
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { AuditEvent } from "./index.js";

/** Build an `onAudit` sink that appends each event as one JSON line. */
export function jsonlAudit(filePath: string): (event: AuditEvent) => void {
  let dirReady = false;
  return (event: AuditEvent) => {
    if (!dirReady) {
      mkdirSync(dirname(filePath), { recursive: true });
      dirReady = true;
    }
    appendFileSync(filePath, `${JSON.stringify(event)}\n`, "utf8");
  };
}
