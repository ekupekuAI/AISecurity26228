/**
 * Cryptographic Inference Provenance
 * Canonical record serialization and SHA-256 tamper verification
 */

import crypto from 'node:crypto';
import { InferenceVerificationResult } from '../../src/types.js';

export class ProvenanceEngine {
  public static canonicalizeRecord(params: {
    inputImageHash: string;
    modelIdentifier: string;
    modelSha256: string;
    preprocessingConfig: string;
    prediction: string;
    confidence: number;
    timestamp: string;
    nonce: string;
  }): string {
    let cleanPreproc = params.preprocessingConfig.trim();
    try {
      const parsed = JSON.parse(cleanPreproc);
      // Deterministically sort keys
      const sortedKeys = Object.keys(parsed).sort();
      const sortedObj: Record<string, unknown> = {};
      for (const k of sortedKeys) {
        sortedObj[k] = parsed[k];
      }
      cleanPreproc = JSON.stringify(sortedObj);
    } catch {
      cleanPreproc = cleanPreproc.replace(/\r\n/g, '\n').trim();
    }

    const confStr = Number(params.confidence).toFixed(6);

    const components = [
      params.inputImageHash.trim().toLowerCase(),
      params.modelIdentifier.trim(),
      params.modelSha256.trim().toLowerCase(),
      cleanPreproc,
      params.prediction.trim(),
      confStr,
      params.timestamp.trim(),
      params.nonce.trim(),
    ];

    return components.join('||');
  }

  public static generateRecordHash(params: {
    inputImageHash: string;
    modelIdentifier: string;
    modelSha256: string;
    preprocessingConfig: string;
    prediction: string;
    confidence: number;
    timestamp: string;
    nonce: string;
  }): { recordHash: string; canonicalString: string } {
    const canonicalString = this.canonicalizeRecord(params);
    const recordHash = crypto.createHash('sha256').update(canonicalString, 'utf8').digest('hex');
    return { recordHash, canonicalString };
  }

  public static verifyRecord(params: {
    expectedHash: string;
    inputImageHash: string;
    modelIdentifier: string;
    modelSha256: string;
    preprocessingConfig: string;
    prediction: string;
    confidence: number;
    timestamp: string;
    nonce: string;
  }): InferenceVerificationResult {
    const { recordHash: computedHash, canonicalString } = this.generateRecordHash(params);
    const isValid = computedHash.toLowerCase() === params.expectedHash.trim().toLowerCase();

    const mismatches: string[] = [];
    if (!isValid) {
      mismatches.push(
        `Cryptographic discrepancy: expected SHA-256 (${params.expectedHash}), but canonical hash recomputed to (${computedHash}). One or more inference parameters have been modified.`
      );
    }

    return {
      status: isValid ? 'VERIFIED' : 'TAMPERED',
      computedHash,
      expectedHash: params.expectedHash,
      canonicalString,
      mismatches,
      verifiedAt: new Date().toISOString(),
    };
  }
}
