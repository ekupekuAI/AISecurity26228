/**
 * Node-wide governance posture: no stale coverage gap.
 *
 * The node-wide view aggregates the whole node, but its coverage-gap signal must reflect the
 * *latest* analysis of each asset. A transient engine outage that was later re-run
 * successfully must not pin the node to REVIEW forever -- that would be stale governance.
 *
 * Isolated database so the aggregate has exactly the rows this test creates.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-govnode-test-'));
process.env.AIA_DATA_DIR = scratch;

const { saveAnalysis } = await import('../db/repositories.js');
const { evaluateGovernance } = await import('./governance.js');

test('a degraded run superseded by a clean re-run does not pin the node to REVIEW', () => {
  const sha = 'f'.repeat(64);
  // First pass: the engine was down, so this asset fell back to the degraded analyser.
  saveAnalysis({
    id: 'MOD-STALE-1', type: 'MODEL', filename: 'x.pth', sha256: sha, fileSizeBytes: 1,
    status: 'SUSPICIOUS', riskScore: 15, engine: 'node-fallback', payload: { modelRisk: 15, findings: [] }, findings: [],
  });
  // Second pass: the engine recovered and the same asset was re-analysed cleanly.
  saveAnalysis({
    id: 'MOD-STALE-2', type: 'MODEL', filename: 'x.pth', sha256: sha, fileSizeBytes: 1,
    status: 'NOT DETECTED', riskScore: 5, engine: 'python-full', payload: { modelRisk: 5, findings: [] }, findings: [],
  });

  const node = evaluateGovernance();
  assert.equal(node.scope, 'PLATFORM');
  // The stale degraded run must not raise a COVERAGE_GAP on the current posture.
  assert.ok(!node.triggeredRules.some((r) => r.startsWith('COVERAGE_GAP')), node.triggeredRules.join(' | '));
  assert.equal(node.decision, 'ACCEPT');
});
