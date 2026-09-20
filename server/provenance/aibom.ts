/**
 * TrustVision AI Bill of Materials (AI-BOM).
 *
 * A signed, portable "passport" for one analysed artifact -- a model or a dataset. It
 * captures the artifact's identity, the assurance verdict, the honest coverage (what was
 * *not* checked), a standards mapping, and a cryptographic seal. Because the seal embeds
 * the issuing node's public key and a canonical-JCS digest, anyone can verify a passport
 * offline, without this platform, using only the file itself.
 *
 * What a verified passport proves: this exact artifact (by SHA-256) was assessed by the
 * holder of a specific Ed25519 key, produced this verdict with these stated limits, and
 * has not been altered since. What it does NOT prove: that the key belongs to whom you
 * think -- that is why the issuer fingerprint is surfaced for out-of-band comparison, the
 * same trust model as any certificate.
 */

import crypto from 'node:crypto';
import { getKeyring, DOMAIN_AIBOM } from '../security/keyring.js';
import { canonicalBytes } from './canonical.js';

const SCHEMA = 'trustvision.aibom/1';

// Ed25519 SPKI DER prefix: 12 fixed bytes, then the 32-byte raw key. Used to rebuild a
// public key from the 32 raw bytes a passport carries.
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export interface AibomAttestation {
  mitreAtlas: string[];
  nistAiRmf: string[];
  cwe: string[];
}

/**
 * Map findings to the control frameworks a real assessment is measured against. Keyed on
 * the stable finding-id prefixes the detectors emit; unknown findings contribute nothing
 * rather than a fabricated mapping.
 */
export function attestationsFor(findings: Array<{ findingId?: string; category?: string }>): AibomAttestation {
  const atlas = new Set<string>();
  const nist = new Set<string>();
  const cwe = new Set<string>();

  for (const f of findings) {
    const id = (f.findingId ?? '').toUpperCase();
    const cat = (f.category ?? '').toUpperCase();

    if (id.startsWith('SEC-') || cat === 'SUPPLY_CHAIN') {
      atlas.add('AML.T0010 ML Supply Chain Compromise');
      cwe.add('CWE-502 Deserialization of Untrusted Data');
      nist.add('MANAGE 2.2 — mechanisms to sustain the value of deployed AI');
    }
    if (id.includes('BACKDOOR') || id.includes('NEURAL-CLEANSE')) {
      atlas.add('AML.T0018 Backdoor ML Model');
      nist.add('MEASURE 2.7 — AI security and resilience are evaluated');
    }
    if (id.includes('TRIGGER') || id.includes('LABEL') || id.includes('DUPLICATE')) {
      atlas.add('AML.T0020 Poison Training Data');
      nist.add('MEASURE 2.7 — AI security and resilience are evaluated');
    }
    if (id.includes('ARCHIVE') || id.includes('ZIP')) {
      cwe.add('CWE-22 Path Traversal');
      cwe.add('CWE-409 Improper Handling of Highly Compressed Data');
    }
    if (id.includes('OOD') || id.includes('SHIFT') || id.includes('DRIFT')) {
      nist.add('MEASURE 2.4 — deployment context and distribution shift are monitored');
    }
  }

  return { mitreAtlas: [...atlas], nistAiRmf: [...nist], cwe: [...cwe] };
}

interface RawFinding {
  findingId?: string;
  finding_id?: string;
  severity?: string;
  detector?: string | null;
  threshold?: string | null;
  category?: string;
  explanation?: string;
}

interface RawCoverage {
  threat?: string;
  technique?: string;
  covered?: boolean;
  confidence?: number;
  limitation?: string;
}

export interface AibomBody {
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
  findings: Array<{ id: string; severity: string; detector: string | null; threshold: string | null }>;
  coverage: Array<{ threat: string; covered: boolean; confidence: number; limitation: string }>;
  attestations: AibomAttestation;
}

export interface AibomSeal {
  canonicalization: string;
  sha256: string;
  signature: string | null;
  signingKeyId: string | null;
  publicKey: string | null;
  publicKeyFingerprint: string | null;
  algorithm: 'Ed25519' | null;
  verificationNote: string;
}

export interface Aibom extends AibomBody {
  seal: AibomSeal;
}

/**
 * Findings that declare a coverage gap: the assessment could not complete, so absence of
 * evidence is not evidence of absence and the passport must never certify ACCEPT. Kept in
 * step with COVERAGE_GAP_IDS in server/routes/governance.ts.
 */
const COVERAGE_GAP_IDS = new Set([
  'SYS-DEGRADED-ANALYSIS',
  'MOD-WHITEBOX-UNAVAILABLE',
  'MOD-TRIGGER-SCAN-INCOMPLETE',
  'MOD-ONNX-BEHAVIOURAL-UNAVAILABLE',
]);

/**
 * Fallback decision, used only when the stored asset-scoped governance verdict is absent.
 * A coverage gap caps it at REVIEW so a passport can never say ACCEPT for an assessment
 * that did not actually run every check.
 */
function decision(riskScore: number, hasCritical: boolean, coverageGap: boolean): string {
  if (hasCritical) return 'QUARANTINE';
  if (riskScore >= 70) return 'QUARANTINE';
  if (coverageGap) return 'REVIEW';
  if (riskScore < 30) return 'ACCEPT';
  return 'REVIEW';
}

/**
 * Build and sign an AI-BOM from a stored analysis payload (as getAnalysisById returns).
 */
export function buildAibom(analysis: Record<string, unknown>, operator: string): Aibom {
  const kind: 'MODEL' | 'DATASET' =
    typeof analysis.modelRisk === 'number' || analysis.framework ? 'MODEL' : 'DATASET';

  const rawFindings = (analysis.findings as RawFinding[] | undefined) ?? [];
  const findings = rawFindings.map((f) => ({
    id: String(f.findingId ?? f.finding_id ?? 'UNKNOWN'),
    severity: String(f.severity ?? 'INFO'),
    detector: (f.detector ?? null) as string | null,
    threshold: (f.threshold ?? null) as string | null,
  }));
  const hasCritical = findings.some((f) => f.severity === 'CRITICAL');

  const rawCoverage = (analysis.coverage as RawCoverage[] | undefined) ?? [];
  const coverage = rawCoverage.map((c) => ({
    threat: String(c.threat ?? ''),
    covered: Boolean(c.covered),
    confidence: Number(c.confidence ?? 0),
    limitation: String(c.limitation ?? ''),
  }));

  const riskScore = Number(
    (kind === 'MODEL' ? analysis.modelRisk : analysis.datasetRisk) ?? analysis.riskScore ?? 0
  );

  // The passport's verdict must match what the console decided for this asset. Prefer the
  // asset-scoped governance decision that analysis.ts already computed and stored (it honours
  // overrides and coverage gaps); only fall back to a local computation when it is absent.
  const coverageGap =
    Boolean(analysis.degraded) ||
    String(analysis.engine ?? '') === 'node-fallback' ||
    rawFindings.some((f) => COVERAGE_GAP_IDS.has(String(f.findingId ?? f.finding_id ?? '')));
  const storedDecision = (analysis.governance as { decision?: string } | undefined)?.decision;

  const body: AibomBody = {
    schema: SCHEMA,
    bomId: `AIBOM-${new Date().getUTCFullYear()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    generatedAt: new Date().toISOString(),
    generatedBy: { node: 'trustvision-node', operator },
    subject: {
      kind,
      filename: String(analysis.filename ?? 'unknown'),
      sha256: String(analysis.sha256 ?? ''),
      sizeBytes: Number(analysis.fileSizeBytes ?? 0),
      ...(kind === 'MODEL'
        ? {
            framework: String(analysis.framework ?? 'unknown'),
            architecture: String(analysis.architecture ?? 'unknown'),
            parameterCount: (analysis.parameterCount as number | null) ?? null,
          }
        : {
            format: String(analysis.format ?? 'unknown'),
            sampleCount: Number(analysis.totalSamples ?? 0),
          }),
    },
    assurance: {
      status: String(analysis.status ?? 'UNKNOWN'),
      decision: storedDecision ?? decision(riskScore, hasCritical, coverageGap),
      riskScore,
      analysisMode: (analysis.analysisMode as string | null) ?? null,
      engine: String(analysis.engine ?? 'unknown'),
      ...(kind === 'MODEL' ? { backdoorConfidence: Number(analysis.backdoorConfidence ?? 0) } : {}),
    },
    metrics: (analysis.metrics as Record<string, unknown>) ?? {},
    findings,
    coverage,
    attestations: attestationsFor(rawFindings),
  };

  // Sign the body. The seal is not part of what is signed -- it wraps it.
  const keyring = getKeyring();
  const sealed = keyring.signDocument(body, DOMAIN_AIBOM);
  const pub = keyring.publicKeyInfo();

  const seal: AibomSeal = {
    canonicalization: 'RFC 8785 JCS',
    sha256: sealed.digest,
    signature: sealed.signature,
    signingKeyId: sealed.keyId,
    publicKey: pub?.publicKey ?? null,
    publicKeyFingerprint: pub?.fingerprint ?? null,
    algorithm: sealed.signature ? 'Ed25519' : null,
    verificationNote:
      'Verify offline: strip seal, canonicalise (RFC 8785 JCS), SHA-256, then check the ' +
      'Ed25519 signature against the embedded public key. Confirm the fingerprint matches ' +
      'the expected issuer out-of-band before trusting the verdict.',
  };

  return { ...body, seal };
}

export type AibomVerification =
  | 'VERIFIED'
  | 'TAMPERED'
  | 'FORGED'
  | 'UNSIGNED'
  | 'MALFORMED';

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

function publicKeyFromRaw(base64: string): crypto.KeyObject | null {
  try {
    const raw = Buffer.from(base64, 'base64');
    if (raw.length !== 32) return null;
    const der = Buffer.concat([SPKI_ED25519_PREFIX, raw]);
    return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

function fingerprintOf(base64: string): string | null {
  try {
    const raw = Buffer.from(base64, 'base64');
    if (raw.length !== 32) return null;
    const digest = crypto.createHash('sha256').update(raw).digest('hex').toUpperCase();
    return (digest.match(/.{1,4}/g) ?? []).slice(0, 8).join(':');
  } catch {
    return null;
  }
}

/**
 * Verify any AI-BOM, including one issued by another node, using the public key the
 * passport carries. The trust decision (is this the issuer I expect?) is surfaced via the
 * fingerprint rather than assumed.
 */
export function verifyAibom(passport: unknown): AibomVerifyResult {
  const now = new Date().toISOString();
  const empty: AibomVerifyResult = {
    status: 'MALFORMED',
    digestMatches: false,
    signatureValid: false,
    computedSha256: '',
    recordedSha256: '',
    issuerFingerprint: null,
    issuedByThisNode: false,
    subject: null,
    decision: null,
    detail: 'The document is not a well-formed AI-BOM.',
    verifiedAt: now,
  };

  if (!passport || typeof passport !== 'object') return empty;
  const doc = passport as Record<string, unknown>;
  const seal = doc.seal as AibomSeal | undefined;
  if (!seal || typeof seal !== 'object') return empty;

  // Everything except the seal is what was signed.
  const { seal: _omit, ...body } = doc;
  const payload = canonicalBytes(body);
  const computed = crypto.createHash('sha256').update(payload).digest('hex');
  const digestMatches = computed === seal.sha256;

  const subject = (doc.subject as { kind?: string; filename?: string; sha256?: string }) ?? null;
  const decisionValue = ((doc.assurance as { decision?: string } | undefined)?.decision as string) ?? null;
  const issuerFingerprint = seal.publicKey ? fingerprintOf(seal.publicKey) : null;

  const localFp = getKeyring().publicKeyInfo()?.fingerprint ?? null;
  const issuedByThisNode = Boolean(issuerFingerprint && localFp && issuerFingerprint === localFp);

  if (!seal.signature || !seal.publicKey) {
    return {
      ...empty,
      status: 'UNSIGNED',
      digestMatches,
      computedSha256: computed,
      recordedSha256: String(seal.sha256 ?? ''),
      issuerFingerprint,
      subject,
      decision: decisionValue,
      detail: 'The passport carries no signature. Its contents cannot be attributed to any issuer.',
    };
  }

  const key = publicKeyFromRaw(seal.publicKey);
  let signatureValid = false;
  if (key) {
    try {
      const message = Buffer.concat([DOMAIN_AIBOM, Buffer.from([0]), payload]);
      const sig = Buffer.from(seal.signature, 'base64');
      signatureValid = sig.length === 64 && crypto.verify(null, message, key, sig);
    } catch {
      signatureValid = false;
    }
  }

  let status: AibomVerification;
  let detail: string;
  if (digestMatches && signatureValid) {
    status = 'VERIFIED';
    detail = issuedByThisNode
      ? 'Digest and signature hold, and the passport was issued by this node.'
      : 'Digest and signature hold. Confirm the issuer fingerprint below matches the node you expect.';
  } else if (!digestMatches) {
    status = 'TAMPERED';
    detail = 'A field was altered after sealing: the recomputed digest does not match.';
  } else {
    status = 'FORGED';
    detail = 'The digest matches but the signature does not verify against the embedded key.';
  }

  return {
    status,
    digestMatches,
    signatureValid,
    computedSha256: computed,
    recordedSha256: String(seal.sha256 ?? ''),
    issuerFingerprint,
    issuedByThisNode,
    subject,
    decision: decisionValue,
    detail,
    verifiedAt: now,
  };
}
