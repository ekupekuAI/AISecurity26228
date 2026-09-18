/**
 * REST client for the assurance console.
 *
 * Authentication is an httpOnly cookie the browser attaches automatically. Nothing
 * credential-bearing is kept in `localStorage`: a token stored there is readable by any
 * injected script, and the previous build kept a full Level-4 session token exactly
 * there.
 *
 * Because the cookie is ambient, every state-changing request must carry the CSRF token
 * the server issued at login. The token is held in module memory only -- it dies with the
 * tab, which is correct, because a fresh tab re-authenticates anyway.
 */

import type {
  AssuranceReport,
  AuditEvent,
  AuthUser,
  ContributorProfile,
  DatasetAnalysisResult,
  DistributionShiftResult,
  EngineHealth,
  Finding,
  GovernanceEvaluation,
  InferenceRecord,
  InferenceVerificationResult,
  ModelAnalysisResult,
  PlatformStats,
  SealedInferenceRecord,
  Aibom,
  AibomSummary,
  AibomVerifyResult,
  SentinelStatus,
  SentinelThreat,
  SystemStatus,
} from '../types.js';

const CSRF_HEADER = 'x-aia-csrf';

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly detail?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /** True when the session is gone and the console should return to the sign-in screen. */
  get isUnauthenticated(): boolean {
    return this.status === 401 || this.code === 'UNAUTHENTICATED';
  }
}

type UnauthenticatedHandler = () => void;
let onUnauthenticated: UnauthenticatedHandler | null = null;

export function setUnauthenticatedHandler(handler: UnauthenticatedHandler | null): void {
  onUnauthenticated = handler;
}

async function request<T>(
  path: string,
  options: { method?: string; body?: unknown; formData?: FormData; signal?: AbortSignal } = {}
): Promise<T> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = {};

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) {
    headers[CSRF_HEADER] = csrfToken;
  }

  let body: BodyInit | undefined;
  if (options.formData) {
    // Deliberately no Content-Type: the browser must set the multipart boundary.
    body = options.formData;
  } else if (options.body !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(options.body);
  }

  const response = await fetch(path, {
    method,
    headers,
    body,
    // Send the session cookie. Same-origin only; the server refuses foreign origins.
    credentials: 'same-origin',
    signal: options.signal,
  });

  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get('content-type') ?? '';
  const payload = contentType.includes('application/json')
    ? await response.json().catch(() => null)
    : await response.text();

  if (!response.ok) {
    const detail = payload as { error?: string; code?: string; issues?: unknown } | null;
    const error = new ApiError(
      detail?.error ?? `Request failed with status ${response.status}`,
      response.status,
      detail?.code,
      detail?.issues ?? detail
    );
    if (error.isUnauthenticated) {
      csrfToken = null;
      onUnauthenticated?.();
    }
    throw error;
  }

  return payload as T;
}

// --- authentication ---------------------------------------------------------

export interface LoginResult {
  user: AuthUser;
  csrfToken: string;
  expiresAt: string;
  notice?: string;
}

export async function login(identifier: string, password: string): Promise<LoginResult> {
  const result = await request<{ user: AuthUser; csrfToken: string; expiresAt: string }>(
    '/api/auth/login',
    { method: 'POST', body: { identifier, password } }
  );
  csrfToken = result.csrfToken;
  return result;
}

/** Read-only evaluation session. Only available when the node runs in demo mode. */
export async function loginAsObserver(): Promise<LoginResult> {
  const result = await request<{ user: AuthUser; csrfToken: string; expiresAt: string; notice: string }>(
    '/api/auth/demo',
    { method: 'POST' }
  );
  csrfToken = result.csrfToken;
  return result;
}

export async function fetchCurrentUser(): Promise<{
  user: AuthUser;
  csrfToken: string;
  expiresAt: string;
  demoMode: boolean;
} | null> {
  try {
    const result = await request<{
      authenticated: boolean;
      user: AuthUser;
      csrfToken: string;
      expiresAt: string;
      demoMode: boolean;
    }>('/api/auth/me');
    csrfToken = result.csrfToken;
    return result;
  } catch (error) {
    if (error instanceof ApiError && error.isUnauthenticated) return null;
    throw error;
  }
}

export async function logout(): Promise<void> {
  await request('/api/auth/logout', { method: 'POST' }).catch(() => undefined);
  csrfToken = null;
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<{ message: string }> {
  return request('/api/auth/change-password', { method: 'POST', body: { currentPassword, newPassword } });
}

// --- analysis ---------------------------------------------------------------

export async function analyzeDataset(file: File, signal?: AbortSignal): Promise<DatasetAnalysisResult> {
  const formData = new FormData();
  formData.append('file', file);
  return request('/api/analyze/dataset', { method: 'POST', formData, signal });
}

export async function analyzeModel(file: File, signal?: AbortSignal): Promise<ModelAnalysisResult> {
  const formData = new FormData();
  formData.append('file', file);
  return request('/api/analyze/model', { method: 'POST', formData, signal });
}

export interface ShiftRequest {
  baselineName: string;
  targetName: string;
  baselineVectors?: number[][];
  targetVectors?: number[][];
  featureNames?: string[];
  baselineFeatures?: Record<string, number>;
  targetFeatures?: Record<string, number>;
  baselineClassRatios?: Record<string, number>;
  targetClassRatios?: Record<string, number>;
}

export async function analyzeDistributionShift(params: ShiftRequest): Promise<DistributionShiftResult> {
  return request('/api/analyze/distribution-shift', { method: 'POST', body: params });
}

export async function listAnalyses(limit = 50, type?: string): Promise<PlatformStats['recentAnalyses']> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (type) query.set('type', type);
  return request(`/api/analysis?${query}`);
}

export async function getAnalysisById(id: string): Promise<Record<string, unknown>> {
  return request(`/api/analysis/${encodeURIComponent(id)}`);
}

export async function listFindings(limit = 100, severity?: string): Promise<Finding[]> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (severity) query.set('severity', severity);
  return request(`/api/findings?${query}`);
}

export async function acknowledgeFinding(id: string): Promise<void> {
  await request(`/api/findings/${encodeURIComponent(id)}/acknowledge`, { method: 'POST' });
}

export async function listContributors(): Promise<ContributorProfile[]> {
  return request('/api/contributors');
}

// --- inference provenance ----------------------------------------------------

export interface SealRequest {
  recordId?: string;
  inputImageSha256: string;
  modelIdentifier: string;
  modelSha256: string;
  inferenceConfig?: Record<string, unknown>;
  prediction: string;
  confidence: number;
  timestampUtc?: string;
  nonce?: string;
}

export async function sealInference(params: SealRequest): Promise<SealedInferenceRecord> {
  return request('/api/inference/seal', { method: 'POST', body: params });
}

export async function verifyInference(
  params: SealRequest & { recordSha256: string; signature?: string | null; signingKeyId?: string | null; checkReplay?: boolean }
): Promise<InferenceVerificationResult> {
  return request('/api/inference/verify', { method: 'POST', body: params });
}

export async function reverifyStoredRecord(id: string): Promise<{
  recordId: string;
  storedStatus: string;
  recomputed: InferenceVerificationResult;
  canonicalDocument: Record<string, unknown>;
}> {
  return request(`/api/inference/${encodeURIComponent(id)}/reverify`);
}

export async function listInferenceRecords(limit = 50): Promise<InferenceRecord[]> {
  return request(`/api/inference-records?limit=${limit}`);
}

export async function fetchPublicKey(): Promise<{
  available: boolean;
  key: { keyId: string; algorithm: string; publicKey: string; fingerprint: string } | null;
  error: string | null;
  canonicalization: string;
  signatureAlgorithm: string;
  note: string;
}> {
  return request('/api/provenance/public-key');
}

// --- governance and audit ----------------------------------------------------

export async function fetchPlatformStats(): Promise<PlatformStats> {
  return request('/api/stats');
}

export async function fetchGovernanceDecision(): Promise<GovernanceEvaluation> {
  return request('/api/governance/decision');
}

export async function fetchGovernanceReport(): Promise<AssuranceReport> {
  return request('/api/governance/report');
}

/** Download the plain-text report. Returns the filename the server chose. */
export async function downloadGovernanceReport(): Promise<string> {
  const response = await fetch('/api/governance/report.txt', { credentials: 'same-origin' });
  if (!response.ok) {
    throw new ApiError('Report download failed.', response.status);
  }
  const disposition = response.headers.get('content-disposition') ?? '';
  const match = disposition.match(/filename="([^"]+)"/);
  const filename = match?.[1] ?? 'assurance-report.txt';

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Revoking immediately can cancel the download in some browsers; a short delay is safe.
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
  return filename;
}

export async function fetchAuditEvents(limit = 100): Promise<AuditEvent[]> {
  return request(`/api/audit-events?limit=${limit}`);
}

export async function verifyAuditChain(): Promise<{
  valid: boolean;
  chainLength: number;
  genesisHash: string;
  headHash: string;
  verifiedBlocks: number;
  signedBlocks: number;
  signatureFailures: number;
  firstBrokenBlock?: { eventId: string; sequence: number; reason: string };
  details: string;
  verifiedAt: string;
}> {
  return request('/api/audit/verify-chain');
}

// --- system -----------------------------------------------------------------

export async function fetchSystemStatus(): Promise<SystemStatus> {
  return request('/api/system/status');
}

export async function fetchEngineHealth(): Promise<EngineHealth> {
  return request('/api/engine/health');
}

export async function updateEngineUrl(engineUrl: string): Promise<{ mlServiceUrl: string; changed: boolean }> {
  return request('/api/system/config', { method: 'POST', body: { engineUrl } });
}

export async function seedEvaluationData(): Promise<{
  message: string;
  tamperDemonstration: {
    sealedPrediction: string;
    presentedPrediction: string;
    sealedDigest: string;
    recomputedDigest: string;
    verificationStatus: string;
    alteredFields: string[];
  };
}> {
  return request('/api/demo/seed', { method: 'POST' });
}

export async function clearEvaluationData(): Promise<{ removed: Record<string, number>; note: string }> {
  return request('/api/demo/clear', { method: 'DELETE' });
}

// --- sentinel ----------------------------------------------------------------

export async function fetchSentinelStatus(): Promise<SentinelStatus> {
  return request('/api/sentinel/status');
}

export async function fetchSentinelThreats(limit = 50): Promise<SentinelThreat[]> {
  return request(`/api/sentinel/threats?limit=${limit}`);
}

export async function triggerSentinelSweep(): Promise<{ ranAt: string }> {
  return request('/api/sentinel/sweep', { method: 'POST' });
}

// --- AI-BOM ------------------------------------------------------------------

export async function generateAibom(analysisId: string): Promise<Aibom> {
  return request('/api/aibom/generate', { method: 'POST', body: { analysisId } });
}

export async function listAiboms(limit = 50): Promise<AibomSummary[]> {
  return request(`/api/aibom?limit=${limit}`);
}

export async function getAibom(bomId: string): Promise<Aibom> {
  return request(`/api/aibom/${encodeURIComponent(bomId)}`);
}

export async function verifyAibom(passport: unknown): Promise<AibomVerifyResult> {
  return request('/api/aibom/verify', { method: 'POST', body: { passport } });
}

/** Download a stored passport as a .aibom.json file. Returns the filename used. */
export async function downloadAibom(bomId: string): Promise<string> {
  const response = await fetch(`/api/aibom/${encodeURIComponent(bomId)}/download`, { credentials: 'same-origin' });
  if (!response.ok) throw new ApiError('Passport download failed.', response.status);
  const filename = `${bomId}.aibom.json`;
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
  return filename;
}
