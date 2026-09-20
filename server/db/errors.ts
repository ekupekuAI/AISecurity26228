/**
 * Lightweight server-fault log.
 *
 * Every 5xx / unhandled exception is written here (in addition to the structured stderr
 * log) so the Sentinel operational sensor can actually see server faults — otherwise a
 * failing gateway leaves no trace any monitor can read.
 *
 * It uses a db handle injected by server/db/index.ts rather than importing it, to avoid an
 * import cycle: server/db/index.ts imports the logger, the logger imports this module, and
 * this module imports nothing. Writes are best-effort and never throw, so a logging failure
 * can never cascade into the request that was already failing.
 */

import type { DatabaseSync } from 'node:sqlite';

let database: DatabaseSync | null = null;

export function bindErrorDb(handle: DatabaseSync): void {
  database = handle;
}

export function recordError(where: string, name: string, message: string, httpStatus?: number): void {
  if (!database) return;
  try {
    database
      .prepare(
        `INSERT INTO error_events (occurred_at, where_at, name, message, http_status)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(new Date().toISOString(), where, name, (message ?? '').slice(0, 500), httpStatus ?? null);
    // Keep the table bounded so a burst of faults cannot grow it without limit.
    database
      .prepare(`DELETE FROM error_events WHERE id NOT IN (SELECT id FROM error_events ORDER BY id DESC LIMIT 2000)`)
      .run();
  } catch {
    // Best-effort: never let error logging cause a second failure.
  }
}

export function countRecentErrors(sinceIso: string): number {
  if (!database) return 0;
  try {
    const row = database
      .prepare(`SELECT COUNT(*) AS v FROM error_events WHERE occurred_at >= ?`)
      .get(sinceIso) as { v: number } | undefined;
    return Number(row?.v ?? 0);
  } catch {
    return 0;
  }
}
