/**
 * AI Integrity Assurance Platform
 * Shared TypeScript definitions
 */

export type AssuranceStatus = 
  | 'DETECTED' 
  | 'SUSPICIOUS' 
  | 'NOT DETECTED' 
  | 'NOT SUPPORTED' 
  | 'ANALYSIS FAILED';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingCategory = 'DATASET' | 'MODEL' | 'INFERENCE' | 'DISTRIBUTION' | 'PROVENANCE';

export interface Finding {
  id: string;
  findingId: string;
  category: FindingCategory;
  severity: FindingSeverity;
  confidence: number; // 0.0 - 1.0
  affectedAsset: string;
  explanation: string;
  evidence: string;
  recommendation: string;
  timestamp: string;
  isDemo?: boolean;
}

export interface DuplicateGroup {
  hash: string;
  filenames: string[];
  sampleCount: number;
}

export interface NearDuplicatePair {
  sampleA: string;
  sampleB: string;
  similarity: number; // 0.0 - 1.0
  metrics: string;
}

export interface AnomalousSample {
  filename: string;
  reason: string;
  anomalyScore: number;
  metric: string;
}

export interface DatasetAnalysisResult {
  id: string;
  filename: string;
  sha256: string;
  fileSizeBytes: number;
  totalSamples: number;
  corruptedFiles: number;
  duplicateFiles: DuplicateGroup[];
  nearDuplicateCandidates: NearDuplicatePair[];
  classDistribution: Record<string, number>;
  suspiciousLabelPatterns: string[];
  anomalousSamples: AnomalousSample[];
  oodIndicators: string[];
  contributorStats: Record<string, number>;
  datasetRisk: number; // 0 - 100
  status: AssuranceStatus;
  findings: Finding[];
  timestamp: string;
  isDemo?: boolean;
}

export interface ModelAnalysisResult {
  id: string;
  filename: string;
  sha256: string;
  fileSizeBytes: number;
  framework: string;
  architecture: string;
  parameterCount: number | null;
  status: AssuranceStatus;
  behavioralAnalysis: string;
  backdoorAnalysis: string;
  confidence: number;
  severity: FindingSeverity;
  evidence: Record<string, unknown>;
  limitations: string;
  modelRisk: number; // 0 - 100
  findings: Finding[];
  timestamp: string;
  isDemo?: boolean;
}

export interface InferenceRecord {
  id: string;
  inputImageHash: string;
  modelIdentifier: string;
  modelSha256: string;
  preprocessingConfig: string;
  prediction: string;
  confidence: number;
  timestamp: string;
  nonce: string;
  recordHash: string;
  status?: 'VERIFIED' | 'TAMPERED';
  isDemo?: boolean;
}

export interface InferenceVerificationResult {
  status: 'VERIFIED' | 'TAMPERED';
  computedHash: string;
  expectedHash: string;
  canonicalString: string;
  mismatches: string[];
  verifiedAt: string;
}

export interface FeatureDrift {
  feature: string;
  driftScore: number; // 0 - 1
  pValue?: number;
  status: 'SHIFT_DETECTED' | 'STABLE' | 'WARNING';
  description: string;
}

export interface DistributionShiftResult {
  id: string;
  baselineName: string;
  targetName: string;
  overallShiftScore: number; // 0 - 100
  status: AssuranceStatus;
  featureDrifts: FeatureDrift[];
  classDistributionDrift: Record<string, { baselineRatio: number; targetRatio: number; delta: number }>;
  findings: Finding[];
  timestamp: string;
  isDemo?: boolean;
}

export interface AuditEvent {
  id: string;
  eventType: string;
  assetName: string;
  assetHash: string;
  severity: FindingSeverity;
  description: string;
  timestamp: string;
  previousHash?: string;
  currentHash?: string;
}

export type GovernanceDecision = 'ACCEPT' | 'REVIEW' | 'QUARANTINE';

export interface AssuranceReport {
  reportId: string;
  generatedAt: string;
  classification: string;
  deployment: string;
  problemStatementId: string;
  datasetAssetId?: string;
  datasetSha256?: string;
  modelAssetId?: string;
  modelSha256?: string;
  datasetRisk: number;
  modelRisk: number;
  distributionShiftRisk: number;
  inferenceIntegrityStatus: 'VERIFIED' | 'TAMPERED';
  overallRisk: number;
  decision: GovernanceDecision;
  actionRequired: string;
  cryptographicSeal: string;
  breakdown: {
    datasetNotes: string[];
    modelNotes: string[];
    shiftNotes: string[];
    inferenceNotes: string[];
  };
}

export interface CanonicalInferenceConfig {
  input_resolution: [number, number];
  mean_norm: [number, number, number];
  std_norm: [number, number, number];
  confidence_threshold: number;
}

export interface CanonicalInferenceRecord {
  record_id: string;
  input_image_sha256: string;
  model_sha256: string;
  inference_config: CanonicalInferenceConfig;
  prediction: string;
  confidence: number;
  timestamp_utc: string;
  nonce: string;
  record_sha256?: string;
  signature?: string;
}

export interface PlatformStats {
  overallTrustScore: number; // 0 - 100
  datasetRisk: number; // 0 - 100
  modelRisk: number; // 0 - 100
  inferenceIntegrityRisk: number; // 0 - 100
  distributionShiftRisk: number; // 0 - 100
  analyzedAssetsCount: number;
  suspiciousFindingsCount: number;
  quarantinedAssetsCount: number;
  recentAnalyses: Array<{
    id: string;
    type: 'DATASET' | 'MODEL' | 'INFERENCE' | 'DISTRIBUTION';
    name: string;
    sha256: string;
    risk: number;
    status: AssuranceStatus;
    timestamp: string;
    isDemo?: boolean;
  }>;
  recentAuditEvents: AuditEvent[];
}

export interface SystemConfig {
  mlServiceUrl: string;
  mlServiceStatus: 'ONLINE' | 'OFFLINE' | 'DEGRADED';
  databasePath: string;
  briefingEngineAvailable: boolean;
  weights: {
    datasetWeight: number;
    modelWeight: number;
    inferenceWeight: number;
    shiftWeight: number;
  };
}

export type UserRole = 
  | 'LEAD_ASSURANCE_ENGINEER' 
  | 'CYBER_SECURITY_AUDITOR' 
  | 'AI_MODEL_VALIDATOR' 
  | 'DEFENSE_INSPECTOR';

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  clearanceLevel: 'LEVEL_4_TOP_SECRET' | 'LEVEL_3_CONFIDENTIAL' | 'LEVEL_2_OPERATIONAL';
  badgeId: string;
  lastLogin: string;
  token?: string;
}
