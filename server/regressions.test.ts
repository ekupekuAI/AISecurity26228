/**
 * Regression tests for the bug-sweep fixes.
 *
 *  - Seeded evaluation data must be owned by the seeding operator, or the per-user dashboard
 *    reads (added with data isolation) show nothing after "Load Evaluation Data".
 *  - An AI-BOM passport must never certify ACCEPT for an analysis with a coverage gap, and
 *    must mirror the stored asset-scoped governance decision when one is present, so a signed
 *    passport can never contradict the on-screen verdict.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-fixes-test-'));
process.env.AIA_DATA_DIR = scratch;

const { listAnalyses, getAnalysisById, ownerTag } = await import('./db/repositories.js');
const { createUser } = await import('./security/accounts.js');
const { seedEvaluationData } = await import('./demo/seed.js');
const { buildAibom } = await import('./provenance/aibom.js');

test('seeded evaluation data is owned by the seeding operator and scoped to their workspace', () => {
  const op = createUser({
    username: 'seed.op', email: 'seed@t.local', name: 'Seed Op',
    role: 'LEAD_ASSURANCE_ENGINEER', password: 'z'.repeat(20),
  });
  seedEvaluationData(op.username, op.id);

  const own = listAnalyses(50, 0, undefined, op.id);
  assert.ok(own.length >= 3, 'the seeding operator sees the seeded analyses on their dashboard');
  assert.ok(
    getAnalysisById(`MOD-EVAL-PREACT-RN18-${ownerTag(op.id)}`, op.id),
    'the seeded model is fetchable by its owner (id namespaced per owner)'
  );

  const other = createUser({
    username: 'other.op', email: 'other@t.local', name: 'Other',
    role: 'CYBER_SECURITY_AUDITOR', password: 'q'.repeat(20),
  });
  assert.equal(
    listAnalyses(50, 0, undefined, other.id).length,
    0,
    'a different operator sees none of the seeded data'
  );
});

test('an AI-BOM passport never certifies ACCEPT for an analysis with a coverage gap', () => {
  const passport = buildAibom(
    {
      filename: 'grey.pth', sha256: 'a'.repeat(64), modelRisk: 6.5, status: 'NOT DETECTED',
      engine: 'python-full',
      findings: [{ findingId: 'MOD-WHITEBOX-UNAVAILABLE', severity: 'LOW' }],
    } as unknown as Record<string, unknown>,
    'seed.op'
  );
  assert.equal(passport.assurance.decision, 'REVIEW', 'a coverage gap caps the passport at REVIEW');
});

test('an AI-BOM passport mirrors the stored asset-scoped governance decision when present', () => {
  const passport = buildAibom(
    {
      filename: 'm.pth', sha256: 'b'.repeat(64), modelRisk: 5, status: 'NOT DETECTED',
      engine: 'python-full', findings: [], governance: { decision: 'QUARANTINE' },
    } as unknown as Record<string, unknown>,
    'seed.op'
  );
  assert.equal(
    passport.assurance.decision,
    'QUARANTINE',
    'the passport uses the stored governance verdict, not a weaker recomputation'
  );
});
