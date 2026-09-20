/**
 * Background analysis jobs.
 *
 * Dataset and model analysis of a large artifact can take minutes on CPU. Doing that inside
 * the HTTP request means the browser holds one connection open with no progress, a slow run
 * is indistinguishable from a hang, and a tunnel/proxy may cut the request mid-analysis.
 *
 * Instead the upload creates a job and returns its id immediately; the analysis runs in the
 * background on the gateway and the console polls the job for status + elapsed, showing a live
 * "still analysing" state and picking up the result when it lands. The job survives the client
 * navigating away, exactly like the rest of the workbench.
 *
 * The registry is in-process (this is a single-node deployment) and pruned so finished jobs do
 * not accumulate.
 */

export type AnalysisJobKind = 'DATASET' | 'MODEL';
export type AnalysisJobStatus = 'running' | 'done' | 'error';

export interface AnalysisJob {
  id: string;
  kind: AnalysisJobKind;
  ownerId?: string;
  filename: string;
  status: AnalysisJobStatus;
  startedAt: number;
  finishedAt?: number;
  result?: Record<string, unknown>;
  error?: string;
}

const jobs = new Map<string, AnalysisJob>();
const RETENTION_MS = 30 * 60 * 1000;
const MAX_JOBS = 200;

function prune(): void {
  const now = Date.now();
  for (const [id, job] of jobs) {
    if (job.finishedAt && now - job.finishedAt > RETENTION_MS) jobs.delete(id);
  }
  // Hard cap as a backstop, dropping the oldest finished jobs first.
  if (jobs.size > MAX_JOBS) {
    const finished = [...jobs.values()].filter((j) => j.finishedAt).sort((a, b) => (a.finishedAt ?? 0) - (b.finishedAt ?? 0));
    for (const job of finished) {
      if (jobs.size <= MAX_JOBS) break;
      jobs.delete(job.id);
    }
  }
}

function newId(): string {
  // Node crypto without importing at top keeps this module dependency-light; require is fine
  // in the CJS bundle the gateway ships as.
  return `job_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

export function createJob(kind: AnalysisJobKind, filename: string, ownerId?: string): AnalysisJob {
  prune();
  const job: AnalysisJob = { id: newId(), kind, ownerId, filename, status: 'running', startedAt: Date.now() };
  jobs.set(job.id, job);
  return job;
}

export function completeJob(id: string, result: Record<string, unknown>): void {
  const job = jobs.get(id);
  if (job) {
    job.status = 'done';
    job.result = result;
    job.finishedAt = Date.now();
  }
}

export function failJob(id: string, error: string): void {
  const job = jobs.get(id);
  if (job) {
    job.status = 'error';
    job.error = error;
    job.finishedAt = Date.now();
  }
}

/** Fetch a job, scoped to its owner so one operator cannot read another's job/result. */
export function getJob(id: string, ownerId?: string): AnalysisJob | null {
  const job = jobs.get(id);
  if (!job) return null;
  if (ownerId && job.ownerId && job.ownerId !== ownerId) return null;
  return job;
}
