/**
 * Python ML Service Bridge & Proxy
 * Communicates with the Python FastAPI ML engine on VITE_ML_SERVICE_URL or ML_SERVICE_URL
 * Transparently falls back to Node's internal deterministic engines if Python service is offline.
 */

import { DatasetAnalyzer } from './analyzers/dataset.js';
import { ModelAnalyzer } from './analyzers/model.js';
import { ProvenanceEngine } from './analyzers/provenance.js';
import { DistributionShiftAnalyzer } from './analyzers/distribution_shift.js';

let configuredMlServiceUrl = process.env.ML_SERVICE_URL || process.env.VITE_ML_SERVICE_URL || 'http://localhost:8000';

export function getMlServiceUrl(): string {
  return configuredMlServiceUrl;
}

export function setMlServiceUrl(url: string): void {
  configuredMlServiceUrl = url.trim().replace(/\/+$/, '');
}

export async function checkMlServiceHealth(): Promise<{
  status: 'ONLINE' | 'OFFLINE';
  url: string;
  details?: Record<string, unknown>;
}> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1200);

    const res = await fetch(`${configuredMlServiceUrl}/health`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return { status: 'ONLINE', url: configuredMlServiceUrl, details: data };
    }
  } catch {
    // Service offline or unreachable
  }
  return { status: 'OFFLINE', url: configuredMlServiceUrl };
}

export async function forwardDatasetAnalysis(
  filename: string,
  buffer: Buffer,
  mimeType: string
) {
  const health = await checkMlServiceHealth();
  if (health.status === 'ONLINE') {
    try {
      const formData = new FormData();
      const blob = new Blob([buffer], { type: mimeType });
      formData.append('file', blob, filename);

      const res = await fetch(`${configuredMlServiceUrl}/analyze/dataset`, {
        method: 'POST',
        body: formData,
      });

      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('Forwarding to Python ML engine failed, falling back to local deterministic engine:', (err as Error).message);
    }
  }

  // Fallback to internal deterministic analyzer
  return DatasetAnalyzer.analyze(filename, buffer);
}

export async function forwardModelAnalysis(
  filename: string,
  buffer: Buffer,
  mimeType: string
) {
  const health = await checkMlServiceHealth();
  if (health.status === 'ONLINE') {
    try {
      const formData = new FormData();
      const blob = new Blob([buffer], { type: mimeType });
      formData.append('file', blob, filename);

      const res = await fetch(`${configuredMlServiceUrl}/analyze/model`, {
        method: 'POST',
        body: formData,
      });

      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('Forwarding to Python ML engine failed, falling back to local deterministic engine:', (err as Error).message);
    }
  }

  // Fallback to internal model analyzer
  return ModelAnalyzer.analyze(filename, buffer);
}

export async function forwardInferenceCreation(record: {
  inputImageHash: string;
  modelIdentifier: string;
  modelSha256: string;
  preprocessingConfig: string;
  prediction: string;
  confidence: number;
  timestamp: string;
  nonce: string;
}) {
  const health = await checkMlServiceHealth();
  if (health.status === 'ONLINE') {
    try {
      const res = await fetch(`${configuredMlServiceUrl}/analyze/inference`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input_image_hash: record.inputImageHash,
          model_identifier: record.modelIdentifier,
          model_sha256: record.modelSha256,
          preprocessing_config: record.preprocessingConfig,
          prediction: record.prediction,
          confidence: record.confidence,
          timestamp: record.timestamp,
          nonce: record.nonce,
        }),
      });

      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('Forwarding to Python ML service failed, falling back to local engine:', (err as Error).message);
    }
  }

  const { recordHash, canonicalString } = ProvenanceEngine.generateRecordHash(record);
  return {
    id: `INF-${Date.now()}-${record.nonce.substring(0, 6)}`,
    ...record,
    recordHash,
    canonicalString,
    status: 'VERIFIED',
  };
}

export async function forwardInferenceVerification(verifyReq: {
  expectedHash: string;
  inputImageHash: string;
  modelIdentifier: string;
  modelSha256: string;
  preprocessingConfig: string;
  prediction: string;
  confidence: number;
  timestamp: string;
  nonce: string;
}) {
  const health = await checkMlServiceHealth();
  if (health.status === 'ONLINE') {
    try {
      const res = await fetch(`${configuredMlServiceUrl}/verify/inference`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          expected_hash: verifyReq.expectedHash,
          input_image_hash: verifyReq.inputImageHash,
          model_identifier: verifyReq.modelIdentifier,
          model_sha256: verifyReq.modelSha256,
          preprocessing_config: verifyReq.preprocessingConfig,
          prediction: verifyReq.prediction,
          confidence: verifyReq.confidence,
          timestamp: verifyReq.timestamp,
          nonce: verifyReq.nonce,
        }),
      });

      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('Forwarding to Python ML service failed, falling back to local engine:', (err as Error).message);
    }
  }

  return ProvenanceEngine.verifyRecord(verifyReq);
}
