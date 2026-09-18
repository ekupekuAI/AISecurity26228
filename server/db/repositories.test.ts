/**
 * Persistence + governance integration.
 *
 * Two properties that matter for correctness under repeated and hostile use: analysing the
 * same asset twice must not accumulate a second copy of its evidence (stale state), and the
 * asset-scoped governance decision recomputed from the persisted record must match what the
 * evidence says -- QUARANTINE for a malicious checkpoint, ACCEPT for a clean corpus -- with
 * no cross-asset contamination.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-repo-test-'));
process.env.AIA_DATA_DIR = scratch;

const { saveAnalysis, findingsForAnalysis } = await import('./repositories.js');
const { assetGovernanceForAnalysis } = await import('../routes/governance.js');

const finding = (id: string, findingId: string, severity: string) => ({
  id,
  findingId,
  category: 'MODEL',
  severity: severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  confidence: 1,
  affectedAsset: 'x',
  explanation: 'e',
  evidence: {},
  recommendation: 'r',
});

test('re-analysis under the same id replaces findings rather than accumulating them', () => {
  const id = 'MOD-IDEMP';
  const sha = 'c'.repeat(64);
  saveAnalysis({
    id, type: 'MODEL', filename: 'm.pth', sha256: sha, fileSizeBytes: 1, status: 'DETECTED', riskScore: 80,
    engine: 'node-fallback', payload: {}, findings: [finding('F1', 'SEC-MALICIOUS-PICKLE-OPCODE', 'CRITICAL'), finding('F2', 'MOD-OUTLIER-NEURONS', 'MEDIUM')],
  });
  // Second run generates fresh (different) engine finding ids, as the real engine does.
  saveAnalysis({
    id, type: 'MODEL', filename: 'm.pth', sha256: sha, fileSizeBytes: 1, status: 'NOT DETECTED', riskScore: 5,
    engine: 'python-full', payload: {}, findings: [finding('F3', 'MOD-OUTLIER-NEURONS', 'MEDIUM')],
  });

  const persisted = findingsForAnalysis(id);
  assert.equal(persisted.length, 1);
  assert.equal(persisted[0].findingId, 'MOD-OUTLIER-NEURONS');
});

test('governance recomputed from a persisted malicious model is QUARANTINE', () => {
  const id = 'MOD-MAL';
  const sha = 'd'.repeat(64);
  saveAnalysis({
    id, type: 'MODEL', filename: 'evil.pth', sha256: sha, fileSizeBytes: 1, status: 'DETECTED', riskScore: 100,
    engine: 'python-full',
    payload: { modelRisk: 100, findings: [finding('X1', 'SEC-MALICIOUS-PICKLE-OPCODE', 'CRITICAL')] },
    findings: [finding('X1', 'SEC-MALICIOUS-PICKLE-OPCODE', 'CRITICAL')],
  });
  const decision = assetGovernanceForAnalysis(id);
  assert.equal(decision?.decision, 'QUARANTINE');
  assert.equal(decision?.subject?.sha256, sha);
});

test('governance recomputed from a persisted clean dataset is ACCEPT, uncontaminated by the malicious model', () => {
  const id = 'DS-CLEAN';
  const sha = 'e'.repeat(64);
  saveAnalysis({
    id, type: 'DATASET', filename: 'clean.zip', sha256: sha, fileSizeBytes: 1, status: 'NOT DETECTED', riskScore: 6,
    engine: 'python-full', payload: { datasetRisk: 6, findings: [] }, findings: [],
  });
  const decision = assetGovernanceForAnalysis(id);
  assert.equal(decision?.decision, 'ACCEPT');
});

test('an unknown analysis id yields no decision', () => {
  assert.equal(assetGovernanceForAnalysis('nope'), null);
});
