/**
 * Shared type definitions.
 *
 * These mirror the engine's wire contract. Where the engine reports something it could
 * *not* do -- a coverage gap, a degraded backbone, a limitation -- the field is present
 * and non-optional so the console cannot quietly omit it. An assurance UI that shows only
 * the findings and hides what was never checked is misleading by construction.
 */

export type AssuranceStatus =
  | 'DETECTED'
  | 'SUSPICIOUS'
  | 'NOT DETECTED'
  | 'NOT SUPPORTED'
  | 'ANALYSIS FAILED';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingCategory =
  | 'DATASET'
  | 'MODEL'
  | 'INFERENCE'
  | 'DISTRIBUTION'
  | 'PROVENANCE'
  | 'SUPPLY_CHAIN';

export type AnalysisMode = 'WHITE_BOX' | 'GREY_BOX' | 'BLACK_BOX' | 'REFUSED';

export type GovernanceDecision = 'ACCEPT' | 'REVIEW' | 'QUARANTINE';

export interface Finding {
  id: string;
  findingId: string;
  category: FindingCategory;
  severity: FindingSeverity;
  /** 0-1. Already scaled by the backbone's own confidence where relevant. */
  confidence: number;
  affectedAsset: string;
  explanation: string;
  evidence: unknown;
  recommendation: string;
  /** The routine that produced this finding, for reproducibility. */
  detector?: string | null;
  /** The exact cut-off that fired, so a reviewer need not read the source. */
  threshold?: string | null;
  references?: string[];
  timestamp: string;
  acknowledgedBy?: string | null;
  acknowledgedAt?: string | null;
  isDemo?: boolean;
}

/** One row of the published attack-coverage matrix. */
export interface CoverageEntry {
  threat: string;
  technique: string;
  covered: boolean;
  confidence: number;
  method: string;
  limitation: string;
  references: string[];
}

// --- dataset ----------------------------------------------------------------

export interface DuplicateGroup {
  hash: string;
  filenames: string[];
  sampleCount: number;
  truncated?: boolean;
}

export interface NearDuplicatePair {
  sampleA: string;
  sampleB: string;
  hammingDistance: number;
  cosineSimilarity: number | null;
  similarity: number;
  contributorA?: string | null;
  contributorB?: string | null;
  metrics: string;
}

export interface TriggerCluster {
  label: string;
  memberCount: number;
  members: string[];
  bbox: [number, number, number, number];
  spatialConsistency: number;
  meanPerturbationMagnitude: number;
  /** The recovered trigger itself, as RGB rows. This is the evidence, not an illustration. */
  recoveredTriggerPatch: number[][][];
  suspectedFamily: string;
  referenceFrame: string;
  familyWisePValue: number;
}

export interface TriggerAnalysis {
  analysedSamples: number;
  candidateCount: number;
  candidates: Array<{
    path: string;
    anomalyScore: number;
    confidence: number;
    bbox: number[];
    bboxOriginal: number[] | null;
    method: string;
    highFrequencyZ: number;
    patchVarianceRatio: number;
    label: string | null;
  }>;
  clusters: TriggerCluster[];
  clusterCount: number;
  confirmedSamples: number;
  consensusAvailable: boolean;
  limitation: string;
}

export interface LabelAnalysis {
  available: boolean;
  analysedSamples: number;
  suspectCount: number;
  suspects: Array<{
    path: string;
    declaredLabel: string;
    projectedLabel: string;
    neighbourDisagreement: number;
    margin: number;
    confidence: number;
  }>;
  classPairFlows: Array<{ fromLabel: string; toLabel: string; count: number; shareOfSourceClass: number }>;
  systematicManipulation: boolean;
  systematicExplanation: string;
  estimatedNoiseRate: number;
  limitation: string;
}

export interface OodAnalysis {
  available: boolean;
  analysedSamples: number;
  outlierCount: number;
  outliers: Array<{
    path: string;
    label: string;
    mahalanobisDistance: number;
    corpusPercentile: number;
    nearestClass: string;
    anomalyScore: number;
  }>;
  thresholdDistance: number;
  medianDistance: number;
  limitation: string;
}

export interface ContributorProfile {
  name: string;
  sampleCount: number;
  exactDuplicates?: number;
  nearDuplicates?: number;
  labelSuspects?: number;
  triggerSamples: number;
  oodSamples?: number;
  corruptSamples?: number;
  totalDefects?: number;
  defectCount?: number;
  defectDensityPercent?: number;
  defectDensity?: number;
  riskScore: number;
  riskDrivers?: string[];
  drivers?: string[];
  /** How many separate submissions this source's totals were aggregated from. */
  submissionCount?: number;
  sourceArchive?: string;
  timestamp?: string;
  isDemo?: boolean;
}

export interface BackboneInfo {
  architecture: string;
  source: 'LOCAL_WEIGHTS' | 'DOWNLOADED' | 'RANDOM_INIT_FALLBACK' | 'UNAVAILABLE';
  weightsSha256: string | null;
  embeddingDim: number;
  confidenceMultiplier: number;
  limitation: string;
}

export interface DatasetAnalysisResult {
  id: string;
  filename: string;
  sha256: string;
  fileSizeBytes: number;
  totalSamples: number;
  decodedSamples: number;
  corruptedFiles: number;
  corruptSampleDetails?: Array<{ path: string; reason: string; detail: string }>;
  format: string;
  layout?: { format: string; classNames: string[]; defects: Array<{ kind: string; location: string; detail: string; severity: string }>; defectCount: number; notes: string[] };
  archive?: { format: string; entriesSeen: number; violations: Array<{ kind: string; entry: string; detail: string }>; violationCount: number; aborted: boolean };
  duplicateFiles: DuplicateGroup[];
  nearDuplicateCandidates: NearDuplicatePair[];
  duplicateAnalysis?: { totalRedundantSamples: number; exactDuplicateSamples: number; nearDuplicateSamples: number; clusterCount: number; embeddingConfirmed: boolean };
  classDistribution: Record<string, number>;
  classImbalanceRatio?: number;
  labelAnalysis?: LabelAnalysis;
  suspiciousLabelPatterns: string[];
  triggerAnalysis?: TriggerAnalysis;
  anomalousSamples: Array<{ filename: string; reason: string; anomalyScore: number; metric: string; bbox?: number[] }>;
  oodAnalysis?: OodAnalysis;
  oodIndicators: string[];
  contributorStats: Record<string, number>;
  contributorProfiles?: ContributorProfile[];
  contributorAttributionStrategy?: string;
  backbone?: BackboneInfo;
  coverage?: CoverageEntry[];
  coverageGaps?: string[];
  riskBreakdown?: Record<string, number>;
  datasetRisk: number;
  status: AssuranceStatus;
  findings: Finding[];
  analysisDurationSeconds?: number;
  engine: string;
  degraded?: boolean;
  degradedReason?: string;
  timestamp: string;
  isDemo?: boolean;
}

// --- model ------------------------------------------------------------------

export interface PickleAudit {
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
  container: string;
  streamsScanned: number;
  opcodeCount: number;
  callOpcodes: number;
  protocolVersions: number[];
  globalsFound: Array<{ module: string; name: string; qualname: string; offset: number }>;
  disallowedGlobals: Array<{ qualname: string; offset: number }>;
  criticalGlobals: Array<{ qualname: string; offset: number }>;
  truncatedStreams: Array<{ stream: string; error: string; opcodesDecodedBeforeFailure: number; bytesUnparsed: number }>;
  notes: string[];
  safeToLoad: boolean;
}

export interface NeuralCleanseReport {
  ran: boolean;
  classesScanned: number;
  classesTotal: number;
  inversions: Array<{
    classIndex: number;
    l1Norm: number;
    l1Fraction: number;
    attackSuccessRate: number;
    anomalyIndex: number;
    l1RatioToMedian: number;
    flagged: boolean;
    maskPreview: number[][];
  }>;
  medianL1: number;
  maxAnomalyIndex: number;
  flaggedClasses: number[];
  backdoorConfidence: number;
  anomalyIndexThreshold: number;
  l1RatioThreshold?: number;
  durationSeconds: number;
  errors: string[];
  limitation: string;
}

export interface BatteryReport {
  ran: boolean;
  inputShape: number[];
  classCount: number;
  cleanPredictionEntropy: number;
  cleanDistribution: Record<string, number>;
  degenerateBaseline: boolean;
  batteries: Array<{
    name: string;
    description: string;
    flipRate: number;
    targetClass: number | null;
    targetShare: number;
    flipConcentration: number;
    liftOverBaseline: number;
    verdict: string;
  }>;
  backdoorConfidence: number;
  suspectedTargetClass: number | null;
  suspectedFamily: string | null;
  limitation: string;
}

export interface WeightStatistics {
  totalParameters: number;
  tensorCount: number;
  dtypeHistogram: Record<string, number>;
  nanTensors: string[];
  infTensors: string[];
  deadTensors: string[];
  outlierNeuronTensors: Array<{ name: string; outlierRowFraction: number; shape: number[] }>;
  anomalyScore: number;
  largestTensors: Array<{ name: string; shape: number[]; parameterCount: number; mean: number; std: number }>;
}

export interface ModelAnalysisResult {
  id: string;
  filename: string;
  sha256: string;
  fileSizeBytes: number;
  framework: string;
  architecture: string;
  parameterCount: number | null;
  analysisMode: AnalysisMode;
  status: AssuranceStatus;
  severity: FindingSeverity;
  confidence: number;
  backdoorConfidence: number;
  behavioralAnalysis: string;
  backdoorAnalysis: string;
  evidence: Record<string, unknown>;
  pickleAudit?: PickleAudit | null;
  torchInspection?: Record<string, unknown> | null;
  onnxInspection?: Record<string, unknown> | null;
  safetensorsInfo?: Record<string, unknown> | null;
  weightStatistics?: WeightStatistics | null;
  behaviouralBattery?: BatteryReport | null;
  neuralCleanse?: NeuralCleanseReport | null;
  coverage?: CoverageEntry[];
  /** Always populated: what the assessment could not establish, in plain language. */
  limitations: string;
  riskBreakdown?: Record<string, number>;
  modelRisk: number;
  findings: Finding[];
  analysisDurationSeconds?: number;
  engine: string;
  degraded?: boolean;
  degradedReason?: string;
  timestamp: string;
  isDemo?: boolean;
}

// --- inference provenance ----------------------------------------------------

export interface SealedInferenceRecord {
  schema: string;
  recordId: string;
  inputImageSha256: string;
  modelIdentifier: string;
  modelSha256: string;
  inferenceConfig: Record<string, unknown>;
  prediction: string;
  confidence: number;
  timestampUtc: string;
  nonce: string;
  recordSha256: string;
  signature: string | null;
  signingKeyId: string | null;
  signatureAlgorithm: 'Ed25519' | null;
  canonicalization: string;
  canonicalString: string;
  signingError: string | null;
  sealedAt: string;
  status?: string;
}

export type VerificationStatus = 'VERIFIED' | 'TAMPERED' | 'FORGED' | 'REPLAYED' | 'UNVERIFIABLE';

export interface InferenceVerificationResult {
  status: VerificationStatus;
  computedHash: string;
  expectedHash: string;
  canonicalString: string;
  signatureValid: boolean | null;
  mismatches: string[];
  /** Named fields that changed, when the original record is on file. */
  alteredFields: string[];
  replay?: { kind?: string; reason?: string; firstSeenAt?: string; originalRecordId?: string } | null;
  staleness?: { stale: boolean; reason?: string; skewSeconds?: number };
  recordId?: string;
  verifiedAt: string;
}

export interface InferenceRecord {
  id: string;
  inputImageHash: string;
  modelIdentifier: string;
  modelSha256: string;
  preprocessingConfig: string;
  configurationHash?: string;
  prediction: string;
  confidence: number;
  timestamp: string;
  nonce: string;
  recordHash: string;
  signature?: string | null;
  signingKeyId?: string | null;
  status: VerificationStatus;
  sealedBy?: string | null;
  isDemo?: boolean;
  createdAt?: string;
}

// --- distribution shift ------------------------------------------------------

export interface FeatureDrift {
  feature: string;
  baselineMean: number;
  targetMean: number;
  driftScore: number;
  ksStatistic: number | null;
  pValue: number | null;
  status: 'SHIFT_DETECTED' | 'STABLE' | 'WARNING';
  description: string;
}

export interface ShiftAttribution {
  verdict: 'ENVIRONMENTAL_DRIFT' | 'SUSPICIOUS_MANIPULATION' | 'MIXED' | 'INSUFFICIENT_EVIDENCE';
  confidence: number;
  displacementConcentration: number;
  photometricExplainedFraction: number;
  outlierSampleCount: number;
  reasoning: string;
}

export interface DistributionShiftResult {
  id: string;
  baselineName: string;
  targetName: string;
  method: string;
  mmd: number;
  mmdSquared: number;
  pValue: number | null;
  significant: boolean;
  severityBand: string;
  attribution: ShiftAttribution | null;
  overallShiftScore: number;
  status: AssuranceStatus;
  featureDrifts: FeatureDrift[];
  classDistributionDrift: Record<string, { baselineRatio: number; targetRatio: number; delta: number }>;
  populationStabilityIndex: number;
  baselineSamples: number;
  targetSamples: number;
  limitation: string;
  findings: Finding[];
  engine: string;
  timestamp: string;
  isDemo?: boolean;
}

// --- audit and governance ----------------------------------------------------

export interface AuditEvent {
  eventId: string;
  sequence: number;
  eventType: string;
  assetId: string | null;
  assetName: string;
  assetHash: string;
  severity: FindingSeverity;
  actor: string;
  description: string;
  metadata: Record<string, unknown>;
  previousHash: string;
  currentHash: string;
  signature: string | null;
  signingKeyId: string | null;
  timestamp: string;
}

export interface GovernanceEvaluation {
  decision: GovernanceDecision;
  actionRequired: string;
  rationale: string;
  triggeredRules: string[];
  thresholds: { acceptBelow: number; quarantineAtOrAbove: number };
  overallRisk: number;
  trustScore: number;
  componentRisks: Record<string, number>;
  evaluatedAt: string;
}

export interface AssuranceReport {
  schema: string;
  reportId: string;
  generatedAt: string;
  generatedBy: string;
  classification: string;
  deployment: string;
  problemStatementId: string;
  assets: {
    dataset: { name: string; sha256: string; status: string; risk: number } | null;
    model: { name: string; sha256: string; status: string; risk: number } | null;
    distributionShift: { name: string; status: string; risk: number } | null;
  };
  risk: {
    datasetRisk: number;
    modelRisk: number;
    distributionShiftRisk: number;
    inferenceIntegrityRisk: number;
    overallRisk: number;
    trustScore: number;
    componentWeights: Record<string, number>;
  };
  inferenceIntegrity: {
    status: string;
    totalRecords: number;
    compromisedRecords: number;
    detail: Array<Record<string, unknown>>;
  };
  findings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    top: Array<Partial<Finding>>;
  };
  contributors: Array<{ name: string; sampleCount: number; defectCount: number; riskScore: number; drivers: string[] }>;
  auditLedger: { valid: boolean; chainLength: number; headHash: string; signedBlocks: number; details: string };
  decision: GovernanceDecision;
  actionRequired: string;
  rationale: string;
  triggeredRules: string[];
  thresholds: { acceptBelow: number; quarantineAtOrAbove: number };
  seal: {
    canonicalization: string;
    sha256: string;
    signature: string | null;
    signingKeyId: string | null;
    algorithm: string | null;
    verificationNote: string;
  };
}

export interface PlatformStats {
  overallTrustScore: number;
  overallRisk: number;
  datasetRisk: number;
  modelRisk: number;
  inferenceIntegrityRisk: number;
  distributionShiftRisk: number;
  analyzedAssetsCount: number;
  suspiciousFindingsCount: number;
  criticalFindingsCount: number;
  quarantinedAssetsCount: number;
  inferenceRecordCount: number;
  tamperedRecordCount: number;
  contributorCount: number;
  highRiskContributorCount: number;
  recentAnalyses: Array<{
    id: string;
    type: 'DATASET' | 'MODEL' | 'INFERENCE' | 'DISTRIBUTION';
    name: string;
    sha256: string;
    risk: number;
    status: AssuranceStatus;
    engine: string;
    analysisMode: string | null;
    durationSeconds: number | null;
    timestamp: string;
    isDemo?: boolean;
    findingCount: number;
    criticalCount: number;
  }>;
  recentAuditEvents: AuditEvent[];
  topContributors: ContributorProfile[];
}

export interface EngineHealth {
  status: 'ONLINE' | 'OFFLINE' | 'DEGRADED';
  url: string;
  details?: Record<string, unknown>;
  error?: string;
  checkedAt: string;
}

export interface SystemStatus {
  service: string;
  version: string;
  environment: string;
  demoMode: boolean;
  timestamp: string;
  engine: {
    url: string;
    status: 'ONLINE' | 'OFFLINE' | 'DEGRADED';
    error: string | null;
    capabilities: Record<string, boolean> | null;
    backbone: BackboneInfo | null;
  };
  database: Record<string, number | string>;
  signing: {
    available: boolean;
    keyId: string;
    publicKey: { keyId: string; algorithm: string; publicKey: string; fingerprint: string; createdAt: string } | null;
    error: string | null;
  };
  auditLedger: { valid: boolean; chainLength: number; signedBlocks: number; headHash: string };
  riskWeights: Record<string, number>;
  decisionThresholds: { acceptBelow: number; quarantineAtOrAbove: number };
  airGapped: boolean;
  statistics: PlatformStats;
}

// --- identity ----------------------------------------------------------------

export type UserRole =
  | 'LEAD_ASSURANCE_ENGINEER'
  | 'CYBER_SECURITY_AUDITOR'
  | 'AI_MODEL_VALIDATOR'
  | 'DEFENSE_INSPECTOR'
  | 'READ_ONLY_OBSERVER';

export type ClearanceLevel = 'LEVEL_4_TOP_SECRET' | 'LEVEL_3_CONFIDENTIAL' | 'LEVEL_2_OPERATIONAL';

export interface AuthUser {
  id: string;
  name: string;
  username: string;
  email: string;
  role: UserRole;
  clearanceLevel: ClearanceLevel;
  badgeId: string;
  lastLogin: string | null;
  isDemoAccount: boolean;
  mustChangePassword: boolean;
  /** Explicit grant list. The console hides actions the session cannot perform. */
  capabilities: string[];
}

// --- sentinel (continuous monitoring) ---------------------------------------

export type SensorId = 'auth' | 'provenance' | 'ledger' | 'supply_chain' | 'traffic';
export type SensorStatus = 'CALIBRATING' | 'NOMINAL' | 'ELEVATED' | 'ALERT';

export interface SentinelSensor {
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
}

export interface SentinelStatus {
  running: boolean;
  intervalSeconds: number;
  lastSweepAt: string | null;
  windowMinutes: number;
  sensors: SentinelSensor[];
  counts: { alerts: number; elevated: number; calibrating: number; nominal: number };
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

// --- AI-BOM (model / dataset passport) --------------------------------------

export interface AibomAttestation {
  mitreAtlas: string[];
  nistAiRmf: string[];
  cwe: string[];
}

export interface Aibom {
  schema: string;
  bomId: string;
  generatedAt: string;
  generatedBy: { node: string; operator: string };
  subject: {
    kind: 'MODEL' | 'DATASET';
    filename: string;
    sha256: string;
    sizeBytes: number;
    framework?: string;
    architecture?: string;
    parameterCount?: number | null;
    format?: string;
    sampleCount?: number;
  };
  assurance: {
    status: string;
    decision: string;
    riskScore: number;
    analysisMode?: string | null;
    engine?: string;
    backdoorConfidence?: number;
  };
  metrics: Record<string, unknown>;
  findings: Array<{ id: string; severity: FindingSeverity; detector: string | null; threshold: string | null }>;
  coverage: Array<{ threat: string; covered: boolean; confidence: number; limitation: string }>;
  attestations: AibomAttestation;
  seal: {
    canonicalization: string;
    sha256: string;
    signature: string | null;
    signingKeyId: string | null;
    publicKey: string | null;
    publicKeyFingerprint: string | null;
    algorithm: 'Ed25519' | null;
    verificationNote: string;
  };
}

export interface AibomSummary {
  bomId: string;
  subjectKind: 'MODEL' | 'DATASET';
  subjectName: string;
  subjectSha256: string;
  status: string;
  decision: string;
  riskScore: number;
  signingKeyId: string | null;
  sha256: string;
  createdBy: string | null;
  createdAt: string;
}

export type AibomVerification = 'VERIFIED' | 'TAMPERED' | 'FORGED' | 'UNSIGNED' | 'MALFORMED';

export interface AibomVerifyResult {
  status: AibomVerification;
  digestMatches: boolean;
  signatureValid: boolean;
  computedSha256: string;
  recordedSha256: string;
  issuerFingerprint: string | null;
  issuedByThisNode: boolean;
  subject: { kind?: string; filename?: string; sha256?: string } | null;
  decision: string | null;
  detail: string;
  verifiedAt: string;
}
