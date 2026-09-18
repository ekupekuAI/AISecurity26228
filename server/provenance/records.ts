/**
 * Canonical inference records: sealing, verification and replay classification.
 *
 * Mirrors `ml-engine/provenance/records.py` exactly, so a record sealed by either process
 * verifies in the other. The canonical document shape is the contract; changing it
 * invalidates every previously sealed record, which is why it carries a schema version.
 *
 * Verification distinguishes four outcomes rather than the usual two, because the
 * response differs for each:
 *
 *   VERIFIED  - digest and signature both hold.
 *   TAMPERED  - digest mismatch. A bound field changed after sealing.
 *   FORGED    - digest holds but the signature does not. Someone recomputed the hash
 *               without the private key. A hash-only scheme cannot see this at all.
 *   REPLAYED  - the record is internally perfect but its nonce was already consumed, or
 *               the same input and model previously produced a different answer.
 */

import crypto from 'node:crypto';
import { canonicalBytes, canonicalize } from './canonical.js';
import { DOMAIN_INFERENCE, getKeyring } from '../security/keyring.js';

export const SCHEMA_VERSION = 'aia-inference/1';

/** Matches the engine's tolerance; air-gapped nodes drift, but not by days. */
export const MAX_CLOCK_SKEW_SECONDS = 24 * 60 * 60;

export interface InferenceRecordInput {
  recordId: string;
  inputImageSha256: string;
  modelIdentifier: string;
  modelSha256: string;
  inferenceConfig: Record<string, unknown>;
  prediction: string;
  confidence: number;
  timestampUtc: string;
  nonce: string;
}

export interface SealedRecord {
  document: Record<string, unknown>;
  canonical: string;
  recordSha256: string;
  signature: string | null;
  signingKeyId: string | null;
  signatureAlgorithm: 'Ed25519' | null;
  canonicalization: 'RFC8785-JCS';
  signingError: string | null;
  sealedAt: string;
}

export type VerificationStatus = 'VERIFIED' | 'TAMPERED' | 'FORGED' | 'REPLAYED' | 'UNVERIFIABLE';

export interface VerificationResult {
  status: VerificationStatus;
  computedHash: string;
  expectedHash: string;
  canonicalString: string;
  signatureValid: boolean | null;
  mismatches: string[];
  alteredFields: string[];
  replay?: Record<string, unknown> | null;
  verifiedAt: string;
}

/**
 * The object that gets canonicalised, hashed and signed.
 *
 * The digest and signature are deliberately absent: a commitment cannot cover itself.
 * Confidence is fixed to six decimals so floating-point representation differences
 * between the sealing and verifying process cannot produce a spurious mismatch.
 */
export function canonicalDocument(record: InferenceRecordInput): Record<string, unknown> {
  return {
    schema: SCHEMA_VERSION,
    recordId: record.recordId,
    inputImageSha256: record.inputImageSha256.trim().toLowerCase(),
    modelIdentifier: record.modelIdentifier.trim(),
    modelSha256: record.modelSha256.trim().toLowerCase(),
    inferenceConfig: record.inferenceConfig,
    prediction: record.prediction.trim(),
    confidence: Number(Number(record.confidence).toFixed(6)),
    timestampUtc: record.timestampUtc.trim(),
    nonce: record.nonce.trim(),
  };
}

export function newNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

export function newRecordId(): string {
  const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  return `INF-${stamp}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

export function seal(record: InferenceRecordInput): SealedRecord {
  const document = canonicalDocument(record);
  const canonical = canonicalize(document);
  const payload = Buffer.from(canonical, 'utf8');
  const recordSha256 = crypto.createHash('sha256').update(payload).digest('hex');

  const keyring = getKeyring();
  const signed = keyring.sign(payload, DOMAIN_INFERENCE);

  return {
    document,
    canonical,
    recordSha256,
    signature: signed?.signature ?? null,
    signingKeyId: signed?.keyId ?? null,
    signatureAlgorithm: signed ? 'Ed25519' : null,
    canonicalization: 'RFC8785-JCS',
    // Surfaced rather than swallowed: an unsigned record is a weaker artefact and the
    // operator has to know that before relying on it.
    signingError: signed ? null : (keyring.error ?? 'No signing key available on this node.'),
    sealedAt: new Date().toISOString(),
  };
}

export function verify(params: {
  record: InferenceRecordInput;
  expectedHash: string;
  signature?: string | null;
  signingKeyId?: string | null;
  reference?: Record<string, unknown> | null;
}): VerificationResult {
  const document = canonicalDocument(params.record);
  const canonical = canonicalize(document);
  const payload = Buffer.from(canonical, 'utf8');
  const computedHash = crypto.createHash('sha256').update(payload).digest('hex');

  const expectedHash = (params.expectedHash ?? '').trim().toLowerCase();
  const hashMatches =
    expectedHash.length === computedHash.length &&
    crypto.timingSafeEqual(Buffer.from(computedHash), Buffer.from(expectedHash));

  const mismatches: string[] = [];
  const alteredFields: string[] = [];
  const verifiedAt = new Date().toISOString();

  let signatureValid: boolean | null = null;
  if (params.signature) {
    const keyring = getKeyring();
    signatureValid = keyring.available
      ? keyring.verify(payload, params.signature, params.signingKeyId, DOMAIN_INFERENCE)
      : null;
    if (signatureValid === null) {
      mismatches.push('A signature was supplied but no verification key is available on this node.');
    }
  }

  if (!hashMatches) {
    mismatches.push(
      `Canonical digest mismatch: recorded ${expectedHash.slice(0, 16)}..., recomputed ` +
        `${computedHash.slice(0, 16)}.... At least one cryptographically bound field was modified after sealing.`
    );

    // Naming the changed field is what turns an alert into something actionable.
    if (params.reference) {
      for (const [key, original] of Object.entries(params.reference)) {
        if (['recordSha256', 'signature', 'signingKeyId', 'canonicalString'].includes(key)) continue;
        const current = (document as Record<string, unknown>)[key];
        if (canonicalize(current ?? null) !== canonicalize(original ?? null)) {
          alteredFields.push(key);
          mismatches.push(
            `Field '${key}': sealed as ${JSON.stringify(original)}, presented as ${JSON.stringify(current)}.`
          );
        }
      }
    }

    return {
      status: 'TAMPERED',
      computedHash,
      expectedHash,
      canonicalString: canonical,
      signatureValid,
      mismatches,
      alteredFields,
      verifiedAt,
    };
  }

  // Digest holds but the signature does not: the payload is internally consistent, so
  // someone recomputed the hash. Only the key holder can produce a valid signature, which
  // makes this forgery rather than corruption.
  if (params.signature && signatureValid === false) {
    return {
      status: 'FORGED',
      computedHash,
      expectedHash,
      canonicalString: canonical,
      signatureValid: false,
      mismatches: [
        'The SHA-256 digest matches, but the Ed25519 signature does not verify. The record was ' +
          're-hashed by a party that does not hold the signing key. This is forgery, not ' +
          'transmission corruption, and a digest-only integrity check would have passed it.',
      ],
      alteredFields: [],
      verifiedAt,
    };
  }

  if (!params.signature) {
    mismatches.push(
      'Digest verified. No signature accompanied this record, so integrity is confirmed but ' +
        'origin is not: any party able to alter the record could also recompute its digest.'
    );
  }

  return {
    status: 'VERIFIED',
    computedHash,
    expectedHash,
    canonicalString: canonical,
    signatureValid,
    mismatches,
    alteredFields: [],
    verifiedAt,
  };
}

/** Seconds by which a record's timestamp differs from now; negative means future-dated. */
export function clockSkewSeconds(timestampUtc: string): number | null {
  const parsed = Date.parse(timestampUtc);
  if (Number.isNaN(parsed)) return null;
  return (Date.now() - parsed) / 1000;
}

export function stalenessVerdict(timestampUtc: string): { stale: boolean; reason?: string; skewSeconds?: number } {
  const skew = clockSkewSeconds(timestampUtc);
  if (skew === null) {
    return { stale: true, reason: 'Record timestamp is not a parseable ISO-8601 instant.' };
  }
  if (Math.abs(skew) > MAX_CLOCK_SKEW_SECONDS) {
    const direction = skew < 0 ? 'in the future' : 'old';
    return {
      stale: true,
      skewSeconds: Math.round(skew),
      reason:
        `Record timestamp is ${(Math.abs(skew) / 3600).toFixed(1)} hours ${direction}, beyond the ` +
        `${MAX_CLOCK_SKEW_SECONDS / 3600}-hour tolerance. Either node clocks have diverged or a ` +
        'captured record is being re-injected.',
    };
  }
  return { stale: false, skewSeconds: Math.round(skew) };
}

export { canonicalBytes };
