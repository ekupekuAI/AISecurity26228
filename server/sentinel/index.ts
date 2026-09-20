/**
 * Sentinel -- continuous local monitoring.
 *
 * A set of sensor agents runs on a timer inside the gateway, reading telemetry that
 * already exists in the database (login attempts, inference records, the audit ledger,
 * analysis findings). Each agent produces one numeric signal per sweep. An adaptive
 * baseline learns what "normal" looks like for that signal and flags deviations; on top
 * of that, some conditions are threats by definition (a broken ledger, a malicious
 * checkpoint, a tampered record) and are raised deterministically regardless of the
 * baseline.
 *
 * What this is, stated honestly:
 *   - Real, adaptive statistical anomaly detection (EWMA mean/variance -> robust z-score)
 *     combined with deterministic hard rules for unambiguous threats.
 *   - It "learns" by updating each sensor's baseline every sweep, so a quiet node grows a
 *     tight baseline and a busy one a wider tolerance.
 *
 * What it is NOT, so no one is misled:
 *   - Not an unbreakable AI. It is a hardened, least-privilege, loopback-only monitor with
 *     an append-only observation log. That is strong; it is not magic.
 *   - It reads; it does not (in this module) take active action. Response hooks are a
 *     deliberate, separate, opt-in layer.
 *
 * Nothing here touches the analysis path. It only observes what that path already records.
 */

import { db, transaction } from '../db/index.js';
import { verifyAuditChain } from '../db/audit.js';
import { checkEngineHealth, getCachedEngineHealth } from '../engineClient.js';
import { countRecentErrors } from '../db/errors.js';
import { log } from '../logger.js';
import type { FindingSeverity } from '../../src/types.js';

export type SensorId = 'auth' | 'provenance' | 'ledger' | 'supply_chain' | 'traffic' | 'operations';
export type SensorStatus = 'CALIBRATING' | 'NOMINAL' | 'ELEVATED' | 'ALERT';

/** How far back each counting sensor looks, and how often the sweep runs. */
const WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_INTERVAL_MS = 45 * 1000;
/** EWMA responsiveness. 0.2 adapts over ~a dozen sweeps without chasing every blip. */
const ALPHA = 0.2;
/** Baseline is not trusted for anomaly calls until it has seen this many sweeps. */
const MIN_SAMPLES = 8;

const SENSOR_LABELS: Record<SensorId, string> = {
  auth: 'Authentication watch',
  provenance: 'Provenance watch',
  ledger: 'Ledger integrity',
  supply_chain: 'Supply-chain scan',
  traffic: 'Traffic anomaly',
  operations: 'Operational health',
};

interface SensorReading {
  sensor: SensorId;
  signal: number;
  summary: string;
  evidence: Record<string, unknown>;
  /** A threat that is unambiguous regardless of the statistical baseline. */
  hardSeverity?: FindingSeverity;
}

interface Observation {
  sensor: SensorId;
  label: string;
  signal: number;
  baseline: number;
  deviation: number;
  severity: FindingSeverity;
  status: SensorStatus;
  summary: string;
  observedAt: string;
  samples: number;
}

function cutoff(): string {
  return new Date(Date.now() - WINDOW_MS).toISOString();
}

function scalar(sql: string, ...params: unknown[]): number {
  const row = db.prepare(sql).get(...(params as [])) as { v: number } | undefined;
  return Number(row?.v ?? 0);
}

// --- sensors ---------------------------------------------------------------------

function senseAuth(): SensorReading {
  const since = cutoff();
  const failed = scalar(
    `SELECT COUNT(*) AS v FROM login_attempts WHERE successful = 0 AND attempted_at >= ?`,
    since
  );
  // Concentrated failures against one identifier are the brute-force signature.
  const worst = db
    .prepare(
      `SELECT identifier, COUNT(*) AS c FROM login_attempts
       WHERE successful = 0 AND attempted_at >= ?
       GROUP BY identifier ORDER BY c DESC LIMIT 1`
    )
    .get(since) as { identifier: string; c: number } | undefined;

  let hardSeverity: FindingSeverity | undefined;
  let summary = failed === 0 ? 'No failed sign-ins in window.' : `${failed} failed sign-in(s) in window.`;
  if (worst && worst.c >= 5) {
    hardSeverity = 'HIGH';
    summary = `${worst.c} failed sign-ins against "${worst.identifier}" — possible brute force.`;
  }
  return { sensor: 'auth', signal: failed, summary, evidence: { failed, worst }, hardSeverity };
}

function senseProvenance(): SensorReading {
  const since = cutoff();
  const compromised = scalar(
    `SELECT COUNT(*) AS v FROM inference_records
     WHERE status IN ('TAMPERED','REPLAYED','FORGED') AND created_at >= ?`,
    since
  );
  const hardSeverity: FindingSeverity | undefined = compromised > 0 ? 'HIGH' : undefined;
  const summary =
    compromised > 0
      ? `${compromised} inference record(s) failed verification (tamper/replay/forge).`
      : 'All inference records verify.';
  return { sensor: 'provenance', signal: compromised, summary, evidence: { compromised }, hardSeverity };
}

function senseLedger(): SensorReading {
  const chain = verifyAuditChain();
  const broken = chain.valid ? 0 : 1;
  return {
    sensor: 'ledger',
    signal: broken,
    summary: chain.valid
      ? `Audit chain intact across ${chain.chainLength} block(s).`
      : `Audit chain BROKEN: ${chain.details}`,
    evidence: { valid: chain.valid, chainLength: chain.chainLength, headHash: chain.headHash },
    hardSeverity: chain.valid ? undefined : 'CRITICAL',
  };
}

function senseSupplyChain(): SensorReading {
  const since = cutoff();
  // A malicious serialisation verdict is the highest-signal supply-chain threat.
  const malicious = scalar(
    `SELECT COUNT(*) AS v FROM findings
     WHERE created_at >= ? AND (finding_id LIKE 'SEC-%' OR category = 'SUPPLY_CHAIN')
       AND severity = 'CRITICAL'`,
    since
  );
  const critical = scalar(
    `SELECT COUNT(*) AS v FROM findings WHERE created_at >= ? AND severity = 'CRITICAL'`,
    since
  );
  let hardSeverity: FindingSeverity | undefined;
  let summary = critical === 0 ? 'No critical findings in window.' : `${critical} critical finding(s) in window.`;
  if (malicious > 0) {
    hardSeverity = 'CRITICAL';
    summary = `${malicious} malicious-artifact finding(s) — a hostile checkpoint or archive was submitted.`;
  } else if (critical > 0) {
    hardSeverity = 'HIGH';
  }
  return { sensor: 'supply_chain', signal: critical, summary, evidence: { malicious, critical }, hardSeverity };
}

function senseTraffic(): SensorReading {
  const since = cutoff();
  const analyses = scalar(`SELECT COUNT(*) AS v FROM analyses WHERE created_at >= ?`, since);
  return {
    sensor: 'traffic',
    signal: analyses,
    // Pure submission throughput. Operational FAILURE (engine down, degraded/failed runs) is
    // owned by the operational sensor below, so this one only flags an unusual volume spike
    // via the statistical baseline rather than pretending a quiet node is a problem.
    summary: `${analyses} analysis submission(s) in window.`,
    evidence: { analyses },
  };
}

/**
 * Operational health: the sensor that surfaces the failures an operator actually sees on the
 * site. It reads already-persisted evidence — ANALYSIS_DEGRADED audit events, analyses that
 * ran on the node fallback or failed, and server faults (5xx) recorded in error_events — plus
 * the cached engine-health snapshot. An unreachable engine is CRITICAL; any degraded/failed
 * run or server error in the window is HIGH. This is why "the website is throwing errors" now
 * shows up in Live Monitoring instead of a misleading all-clear.
 */
function senseOperations(): SensorReading {
  const since = cutoff();
  const degraded = scalar(
    `SELECT COUNT(*) AS v FROM audit_events WHERE event_type = 'ANALYSIS_DEGRADED' AND timestamp >= ?`,
    since
  );
  const failed = scalar(
    `SELECT COUNT(*) AS v FROM analyses WHERE created_at >= ? AND (engine = 'node-fallback' OR status LIKE '%FAIL%')`,
    since
  );
  const errors = countRecentErrors(since);
  const health = getCachedEngineHealth();
  const engineOffline = health?.status === 'OFFLINE';
  const signal = degraded + failed + errors + (engineOffline ? 1 : 0);

  let hardSeverity: FindingSeverity | undefined;
  let summary = 'Assurance engine reachable; no degraded analyses or server errors in window.';
  if (engineOffline) {
    hardSeverity = 'CRITICAL';
    summary =
      `Assurance engine OFFLINE. ${degraded} degraded / ${failed} failed analysis(es) and ` +
      `${errors} server error(s) in the last 15 min — every analysis is running degraded.`;
  } else if (degraded > 0 || failed > 0 || errors > 0) {
    hardSeverity = 'HIGH';
    summary = `${degraded} degraded, ${failed} failed analysis(es) and ${errors} server error(s) in the last 15 min.`;
  }
  return {
    sensor: 'operations',
    signal,
    summary,
    evidence: { degraded, failed, errors, engineStatus: health?.status ?? 'UNKNOWN' },
    hardSeverity,
  };
}

const SENSORS: Array<() => SensorReading> = [
  senseAuth,
  senseProvenance,
  senseLedger,
  senseSupplyChain,
  senseTraffic,
  senseOperations,
];

// --- adaptive baseline + scoring -------------------------------------------------

interface BaselineState {
  mean: number;
  var: number;
  samples: number;
}

function loadState(sensor: SensorId): BaselineState {
  const row = db
    .prepare(`SELECT ewma_mean, ewma_var, samples FROM sentinel_state WHERE sensor = ?`)
    .get(sensor) as { ewma_mean: number; ewma_var: number; samples: number } | undefined;
  return row
    ? { mean: row.ewma_mean, var: row.ewma_var, samples: row.samples }
    : { mean: 0, var: 0, samples: 0 };
}

function updateState(sensor: SensorId, signal: number, next: BaselineState): void {
  db.prepare(
    `INSERT INTO sentinel_state (sensor, ewma_mean, ewma_var, samples, last_signal, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(sensor) DO UPDATE SET
       ewma_mean = excluded.ewma_mean, ewma_var = excluded.ewma_var,
       samples = excluded.samples, last_signal = excluded.last_signal, updated_at = excluded.updated_at`
  ).run(sensor, next.mean, next.var, next.samples, signal, new Date().toISOString());
}

const SEVERITY_RANK: Record<FindingSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function worse(a: FindingSeverity, b: FindingSeverity): FindingSeverity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/** Score one reading against its adaptive baseline and any hard rule. */
function score(reading: SensorReading): Observation {
  const prior = loadState(reading.sensor);
  // Floor the standard deviation at 1. These signals are integer counts, and after a quiet
  // calibration the EWMA variance collapses toward 0; without a floor a single unit of change
  // becomes a thousands-of-sigma spurious ALERT. One count of movement is never an alert.
  const std = Math.max(Math.sqrt(prior.var), 1);
  const deviation = prior.samples >= MIN_SAMPLES ? (reading.signal - prior.mean) / std : 0;

  // Update EWMA *after* scoring, so a reading is judged against the past, not itself.
  const mean = prior.samples === 0 ? reading.signal : (1 - ALPHA) * prior.mean + ALPHA * reading.signal;
  const varNext =
    prior.samples === 0 ? 0 : (1 - ALPHA) * prior.var + ALPHA * (reading.signal - prior.mean) ** 2;
  const nextState = { mean, var: varNext, samples: prior.samples + 1 };
  updateState(reading.sensor, reading.signal, nextState);

  // Statistical severity from the deviation.
  let statistical: FindingSeverity = 'INFO';
  if (deviation >= 4) statistical = 'HIGH';
  else if (deviation >= 3) statistical = 'MEDIUM';
  else if (deviation >= 2) statistical = 'LOW';

  const severity = worse(statistical, reading.hardSeverity ?? 'INFO');

  let status: SensorStatus;
  if (prior.samples < MIN_SAMPLES && !reading.hardSeverity) status = 'CALIBRATING';
  else if (SEVERITY_RANK[severity] >= SEVERITY_RANK.HIGH) status = 'ALERT';
  else if (SEVERITY_RANK[severity] >= SEVERITY_RANK.LOW) status = 'ELEVATED';
  else status = 'NOMINAL';

  return {
    sensor: reading.sensor,
    label: SENSOR_LABELS[reading.sensor],
    signal: reading.signal,
    baseline: Number(prior.mean.toFixed(3)),
    deviation: Number(deviation.toFixed(2)),
    severity,
    status,
    summary: reading.summary,
    observedAt: new Date().toISOString(),
    samples: nextState.samples,
  };
}

// --- sweep + scheduler -----------------------------------------------------------

let lastSweepAt: string | null = null;
let timer: ReturnType<typeof setInterval> | null = null;
let intervalMs = DEFAULT_INTERVAL_MS;

export function runSentinelSweep(): Observation[] {
  // Refresh the engine-health snapshot for the operational sensor (async, fire-and-forget;
  // the sensor reads the cached value synchronously, so this sweep uses the prior snapshot
  // and the next sweep sees the fresh one).
  void checkEngineHealth();
  return transaction(() => {
    const observations: Observation[] = [];
    for (const sensor of SENSORS) {
      let reading: SensorReading;
      try {
        reading = sensor();
      } catch (error) {
        // A sensor failure is itself worth recording rather than hiding.
        log.warn('sentinel sensor failed', { error: error instanceof Error ? error.message : String(error) });
        continue;
      }
      const obs = score(reading);
      db.prepare(
        `INSERT INTO sentinel_observations
           (observed_at, sensor, signal, baseline, deviation, severity, status, summary, evidence_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        obs.observedAt,
        obs.sensor,
        obs.signal,
        obs.baseline,
        obs.deviation,
        obs.severity,
        obs.status,
        obs.summary,
        JSON.stringify(reading.evidence)
      );
      observations.push(obs);
    }
    lastSweepAt = new Date().toISOString();
    return observations;
  });
}

export function startSentinel(customIntervalMs?: number): void {
  if (timer) return;
  intervalMs = customIntervalMs ?? DEFAULT_INTERVAL_MS;
  // One immediate sweep so the page has data at once, then on the interval.
  try {
    runSentinelSweep();
  } catch (error) {
    log.warn('initial sentinel sweep failed', { error: error instanceof Error ? error.message : String(error) });
  }
  timer = setInterval(() => {
    try {
      runSentinelSweep();
    } catch (error) {
      log.warn('sentinel sweep failed', { error: error instanceof Error ? error.message : String(error) });
    }
  }, intervalMs);
  timer.unref?.();
  log.info('sentinel started', { intervalSeconds: Math.round(intervalMs / 1000) });
}

export function stopSentinel(): void {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

// --- read models for the API -----------------------------------------------------

export interface SentinelStatus {
  running: boolean;
  intervalSeconds: number;
  lastSweepAt: string | null;
  windowMinutes: number;
  sensors: Array<{
    sensor: SensorId;
    label: string;
    status: SensorStatus;
    severity: FindingSeverity;
    signal: number;
    baseline: number;
    deviation: number;
    samples: number;
    summary: string;
    observedAt: string;
  }>;
  counts: { alerts: number; elevated: number; calibrating: number; nominal: number };
}

export function sentinelStatus(): SentinelStatus {
  const latest = db
    .prepare(
      `SELECT o.* FROM sentinel_observations o
       JOIN (SELECT sensor, MAX(id) AS mid FROM sentinel_observations GROUP BY sensor) last
         ON o.id = last.mid
       ORDER BY o.sensor`
    )
    .all() as Array<Record<string, unknown>>;

  const counts = { alerts: 0, elevated: 0, calibrating: 0, nominal: 0 };
  const sensors = latest.map((row) => {
    const status = String(row.status) as SensorStatus;
    if (status === 'ALERT') counts.alerts += 1;
    else if (status === 'ELEVATED') counts.elevated += 1;
    else if (status === 'CALIBRATING') counts.calibrating += 1;
    else counts.nominal += 1;
    const sensor = String(row.sensor) as SensorId;
    const stateRow = db.prepare(`SELECT samples FROM sentinel_state WHERE sensor = ?`).get(sensor) as
      | { samples: number }
      | undefined;
    return {
      sensor,
      label: SENSOR_LABELS[sensor] ?? sensor,
      status,
      severity: String(row.severity) as FindingSeverity,
      signal: Number(row.signal),
      baseline: Number(row.baseline),
      deviation: Number(row.deviation),
      samples: Number(stateRow?.samples ?? 0),
      summary: String(row.summary),
      observedAt: String(row.observed_at),
    };
  });

  return {
    running: timer !== null,
    intervalSeconds: Math.round(intervalMs / 1000),
    lastSweepAt,
    windowMinutes: Math.round(WINDOW_MS / 60000),
    sensors,
    counts,
  };
}

export interface SentinelThreat {
  id: number;
  observedAt: string;
  sensor: SensorId;
  label: string;
  severity: FindingSeverity;
  status: SensorStatus;
  summary: string;
}

/** Recent non-nominal observations -- "what the agents have flagged so far". */
export function recentThreats(limit = 50): SentinelThreat[] {
  const rows = db
    .prepare(
      `SELECT id, observed_at, sensor, severity, status, summary
       FROM sentinel_observations
       WHERE status IN ('ALERT','ELEVATED')
       ORDER BY id DESC LIMIT ?`
    )
    .all(Math.min(Math.max(limit, 1), 200)) as Array<Record<string, unknown>>;
  return rows.map((row) => ({
    id: Number(row.id),
    observedAt: String(row.observed_at),
    sensor: String(row.sensor) as SensorId,
    label: SENSOR_LABELS[String(row.sensor) as SensorId] ?? String(row.sensor),
    severity: String(row.severity) as FindingSeverity,
    status: String(row.status) as SensorStatus,
    summary: String(row.summary),
  }));
}
