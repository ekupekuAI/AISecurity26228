/**
 * AI Integrity Assurance Platform - REST API Client
 * Connects frontend to the Node.js assurance server and Python ML engine
 */

import {
  AssuranceReport,
  AuditEvent,
  AuthUser,
  CanonicalInferenceRecord,
  DatasetAnalysisResult,
  DistributionShiftResult,
  Finding,
  GovernanceDecision,
  InferenceRecord,
  InferenceVerificationResult,
  ModelAnalysisResult,
  PlatformStats,
  SystemConfig,
  UserRole,
} from '../types.js';

const API_BASE = ''; // Same origin (port 3000)

export function getAuthToken(): string | null {
  try {
    return localStorage.getItem('ai_integrity_token');
  } catch {
    return null;
  }
}

export function setAuthToken(token: string | null): void {
  try {
    if (token) {
      localStorage.setItem('ai_integrity_token', token);
    } else {
      localStorage.removeItem('ai_integrity_token');
    }
  } catch {
    // Ignore storage issues
  }
}

function getAuthHeaders(): Record<string, string> {
  const token = getAuthToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function loginWithCredentials(identifier: string, password: string): Promise<AuthUser> {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, password }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Authentication failed' }));
    throw new Error(err.error || 'Authentication failed');
  }

  const data = await res.json();
  if (data.user?.token) {
    setAuthToken(data.user.token);
  }
  return data.user;
}

export async function quickRoleLogin(role: UserRole): Promise<AuthUser> {
  const res = await fetch(`${API_BASE}/api/auth/quick-role`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Failed to initiate role session' }));
    throw new Error(err.error || 'Failed to initiate role session');
  }

  const data = await res.json();
  if (data.user?.token) {
    setAuthToken(data.user.token);
  }
  return data.user;
}

export async function fetchCurrentUser(): Promise<AuthUser | null> {
  const token = getAuthToken();
  if (!token) return null;

  try {
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { ...getAuthHeaders() },
    });
    if (!res.ok) {
      setAuthToken(null);
      return null;
    }
    const data = await res.json();
    return data.user;
  } catch {
    return null;
  }
}

export async function logoutUser(): Promise<void> {
  setAuthToken(null);
  await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST' }).catch(() => {});
}

export async function fetchHealth(): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/health`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}

export async function analyzeDataset(file: File): Promise<DatasetAnalysisResult> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/analyze/dataset`, {
    method: 'POST',
    headers: { ...getAuthHeaders() },
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Dataset analysis failed');
  }

  return res.json();
}

export async function analyzeModel(file: File): Promise<ModelAnalysisResult> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/analyze/model`, {
    method: 'POST',
    headers: { ...getAuthHeaders() },
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Model analysis failed');
  }

  return res.json();
}

export async function createInferenceRecord(params: {
  inputImageHash: string;
  modelIdentifier: string;
  modelSha256: string;
  preprocessingConfig: string;
  prediction: string;
  confidence: number;
  timestamp?: string;
  nonce?: string;
}): Promise<InferenceRecord> {
  const res = await fetch(`${API_BASE}/analyze/inference`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify(params),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Inference record creation failed');
  }

  return res.json();
}

export async function verifyInferenceRecord(params: {
  expectedHash: string;
  inputImageHash: string;
  modelIdentifier: string;
  modelSha256: string;
  preprocessingConfig: string;
  prediction: string;
  confidence: number;
  timestamp: string;
  nonce: string;
}): Promise<InferenceVerificationResult> {
  const res = await fetch(`${API_BASE}/verify/inference`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify(params),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Inference verification failed');
  }

  return res.json();
}

export async function getAnalysisById(id: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/analysis/${encodeURIComponent(id)}`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error(`Failed to load analysis: ${res.statusText}`);
  return res.json();
}

export async function listAnalyses(): Promise<PlatformStats['recentAnalyses']> {
  const res = await fetch(`${API_BASE}/analysis`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error(`Failed to load analyses: ${res.statusText}`);
  return res.json();
}

export async function listFindings(): Promise<Finding[]> {
  const res = await fetch(`${API_BASE}/findings`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error(`Failed to load findings: ${res.statusText}`);
  return res.json();
}

export async function fetchPlatformStats(): Promise<PlatformStats> {
  const res = await fetch(`${API_BASE}/api/stats`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error(`Failed to fetch stats: ${res.statusText}`);
  return res.json();
}

export async function fetchInferenceRecords(): Promise<InferenceRecord[]> {
  const res = await fetch(`${API_BASE}/api/inference-records`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error(`Failed to fetch inference records: ${res.statusText}`);
  return res.json();
}

export async function fetchAuditEvents(): Promise<AuditEvent[]> {
  const res = await fetch(`${API_BASE}/api/audit-events`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error(`Failed to fetch audit events: ${res.statusText}`);
  return res.json();
}

export async function analyzeDistributionShift(params: {
  baselineName: string;
  targetName: string;
  baselineFeatures?: Record<string, number>;
  targetFeatures?: Record<string, number>;
  baselineClassRatios?: Record<string, number>;
  targetClassRatios?: Record<string, number>;
}): Promise<DistributionShiftResult> {
  const res = await fetch(`${API_BASE}/api/analyze/distribution-shift`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify(params),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Distribution shift analysis failed');
  }

  return res.json();
}

export async function explainFindingsWithGemini(findings: Finding[]): Promise<string> {
  const res = await fetch(`${API_BASE}/api/gemini/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ findings }),
  });

  if (!res.ok) throw new Error('AI explanation failed');
  const data = await res.json();
  return data.briefing;
}

export async function seedDemoData(): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/api/demo/seed`, {
    method: 'POST',
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error('Failed to seed demo data');
  return res.json();
}

export async function clearDemoData(): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/api/demo/clear`, {
    method: 'DELETE',
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error('Failed to clear demo data');
  return res.json();
}

export async function fetchSystemConfig(): Promise<SystemConfig> {
  const res = await fetch(`${API_BASE}/api/system/config`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error('Failed to load system config');
  return res.json();
}

export async function updateSystemConfig(params: { mlServiceUrl: string }): Promise<void> {
  const res = await fetch(`${API_BASE}/api/system/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error('Failed to update system config');
}

export async function verifyAuditChain(): Promise<{
  valid: boolean;
  chainLength: number;
  genesisHash: string;
  headHash: string;
  tamperedEventId?: string;
  details: string;
}> {
  const res = await fetch(`${API_BASE}/api/audit/verify-chain`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error('Failed to verify audit ledger chain');
  return res.json();
}

export async function fetchGovernanceDecision(): Promise<{
  decision: GovernanceDecision;
  actionRequired: string;
  rationale: string;
  overallRisk: number;
  trustScore: number;
  evaluatedAt: string;
}> {
  const res = await fetch(`${API_BASE}/api/governance/decision`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error('Failed to fetch governance decision');
  return res.json();
}

export async function fetchGovernanceReport(): Promise<AssuranceReport> {
  const res = await fetch(`${API_BASE}/api/governance/report`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) throw new Error('Failed to fetch governance assurance report');
  return res.json();
}

export async function createCanonicalInference(record: Partial<CanonicalInferenceRecord>): Promise<CanonicalInferenceRecord> {
  const res = await fetch(`${API_BASE}/api/inference/canonical`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify(record),
  });
  if (!res.ok) throw new Error('Failed to seal canonical inference');
  return res.json();
}

export async function verifyCanonicalInference(record: Partial<CanonicalInferenceRecord>): Promise<InferenceVerificationResult> {
  const res = await fetch(`${API_BASE}/api/inference/verify-canonical`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify(record),
  });
  if (!res.ok) throw new Error('Failed to verify canonical inference');
  return res.json();
}

