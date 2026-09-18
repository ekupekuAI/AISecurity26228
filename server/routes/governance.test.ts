/**
 * Asset-scoped governance: the decision for one asset must be a function of that asset's
 * own evidence, and only that.
 *
 * The bug this suite pins down: the node-wide composite decision could not tell one asset
 * from another, so a malicious checkpoint uploaded a minute before a clean dataset made the
 * clean dataset show QUARANTINE too. These tests assert the two decisions are independent,
 * that a fatal override fires regardless of a low score, and -- critically for the "no
 * silent degradation" requirement -- that a degraded or behaviourally-incomplete assessment
 * can never reach ACCEPT.
 *
 * The database is redirected to a throwaway directory before any module that opens it is
 * imported, so the suite touches no real evidence store.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-gov-test-'));
process.env.AIA_DATA_DIR = scratch;

const { evaluateAssetGovernance, assetGovernanceForAnalysis } = await import('./governance.js');

type Finding = Record<string, unknown>;
const finding = (findingId: string, severity: string, extra: Finding = {}): Finding => ({
  findingId,
  severity,
  confidence: 1,
  ...extra,
});

const asset = (over: Partial<Parameters<typeof evaluateAssetGovernance>[0]>) =>
  evaluateAssetGovernance({
    analysisId: 'A-1',
    type: 'DATASET',
    filename: 'sample',
    sha256: 'a'.repeat(64),
    risk: 0,
    engine: 'python-full',
    degraded: false,
    findings: [],
    ...over,
  });

test('a clean, low-risk asset is ACCEPTed', () => {
  const decision = asset({ type: 'DATASET', risk: 5 });
  assert.equal(decision.decision, 'ACCEPT');
  assert.equal(decision.scope, 'ASSET');
  assert.equal(decision.subject?.analysisId, 'A-1');
});

test('risk in the review band yields REVIEW', () => {
  assert.equal(asset({ type: 'DATASET', risk: 45 }).decision, 'REVIEW');
});

test('risk at or above the quarantine band yields QUARANTINE', () => {
  assert.equal(asset({ type: 'DATASET', risk: 75 }).decision, 'QUARANTINE');
});

test('a malicious checkpoint QUARANTINEs by override even at risk 0', () => {
  const decision = asset({
    type: 'MODEL',
    risk: 0,
    findings: [finding('SEC-MALICIOUS-PICKLE-OPCODE', 'CRITICAL')],
  });
  assert.equal(decision.decision, 'QUARANTINE');
  assert.ok(decision.triggeredRules.some((r) => r.startsWith('MALICIOUS_SERIALIZATION')));
});

test('a confirmed backdoor QUARANTINEs by override', () => {
  const decision = asset({
    type: 'MODEL',
    risk: 60,
    findings: [finding('MOD-NEURAL-CLEANSE-TRIGGER', 'CRITICAL')],
  });
  assert.equal(decision.decision, 'QUARANTINE');
  assert.ok(decision.triggeredRules.some((r) => r.startsWith('BACKDOOR_CONFIRMED')));
});

test('a degraded (engine-down) assessment cannot be ACCEPTed', () => {
  const decision = asset({
    type: 'MODEL',
    risk: 10,
    engine: 'node-fallback',
    degraded: true,
    findings: [finding('SYS-DEGRADED-ANALYSIS', 'MEDIUM')],
  });
  assert.equal(decision.decision, 'REVIEW');
  assert.ok(decision.triggeredRules.some((r) => r.startsWith('COVERAGE_GAP')));
});

test('an ONNX model that could not be executed cannot be ACCEPTed', () => {
  const decision = asset({
    type: 'MODEL',
    risk: 4,
    findings: [finding('MOD-ONNX-BEHAVIOURAL-UNAVAILABLE', 'LOW')],
  });
  assert.equal(decision.decision, 'REVIEW');
});

test('decisions are scoped: a malicious model does not condemn a clean dataset', () => {
  const malicious = asset({
    analysisId: 'MOD-1',
    type: 'MODEL',
    risk: 100,
    findings: [finding('SEC-MALICIOUS-PICKLE-OPCODE', 'CRITICAL')],
  });
  const cleanDataset = asset({
    analysisId: 'DS-1',
    type: 'DATASET',
    risk: 6,
    findings: [],
  });

  assert.equal(malicious.decision, 'QUARANTINE');
  assert.equal(cleanDataset.decision, 'ACCEPT');
  // Each decision names only its own subject.
  assert.equal(malicious.subject?.analysisId, 'MOD-1');
  assert.equal(cleanDataset.subject?.analysisId, 'DS-1');
});

test('an unacknowledged CRITICAL finding overrides to QUARANTINE', () => {
  const decision = asset({ type: 'DATASET', risk: 10, findings: [finding('DS-SOMETHING', 'CRITICAL')] });
  assert.equal(decision.decision, 'QUARANTINE');
});

test('an acknowledged CRITICAL finding does not override', () => {
  const decision = asset({
    type: 'DATASET',
    risk: 10,
    findings: [finding('DS-SOMETHING', 'CRITICAL', { acknowledgedAt: new Date().toISOString() })],
  });
  assert.equal(decision.decision, 'ACCEPT');
});

test('assetGovernanceForAnalysis returns null for an unknown id', () => {
  assert.equal(assetGovernanceForAnalysis('does-not-exist'), null);
});
