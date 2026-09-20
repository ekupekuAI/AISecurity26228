/**
 * Per-user data isolation, plus cross-user passport verification.
 *
 * Two properties the multi-operator console must hold at once:
 *  1. One operator never sees another's evidence. Every dashboard/history/findings/stats
 *     read is scoped to the owning user, and two operators who analyse the *same file* get
 *     independent rows (the id is namespaced by owner) rather than colliding on one.
 *  2. A signed passport still crosses that boundary. Verification is pure cryptography, so
 *     a passport one user issues verifies for anyone -- even though another user cannot
 *     list or download it from the issuer's workspace.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-isolation-test-'));
process.env.AIA_DATA_DIR = scratch;

const {
  saveAnalysis,
  listAnalyses,
  getAnalysisById,
  platformStatistics,
  listAiboms,
  getAibom,
  saveAibom,
  ownerTag,
} = await import('./repositories.js');
const { createUser } = await import('../security/accounts.js');
const { buildAibom, verifyAibom } = await import('../provenance/aibom.js');

const alice = createUser({
  username: 'alice.test', email: 'alice@t.local', name: 'Alice',
  role: 'CYBER_SECURITY_AUDITOR', password: 'x'.repeat(20),
});
const bob = createUser({
  username: 'bob.test', email: 'bob@t.local', name: 'Bob',
  role: 'CYBER_SECURITY_AUDITOR', password: 'y'.repeat(20),
});

const critical = {
  id: 'FC', findingId: 'SEC-MALICIOUS-PICKLE-OPCODE', category: 'MODEL',
  severity: 'CRITICAL' as const, confidence: 1, affectedAsset: 'x', explanation: 'e',
  evidence: {}, recommendation: 'r',
};

// Both operators analyse the SAME file (same digest). The route namespaces the id by owner,
// which is what keeps them from colliding on one shared row -- reproduced here.
const sharedSha = 'a'.repeat(64);
const aliceId = `MOD-SHARED-${ownerTag(alice.id)}`;
const bobId = `MOD-SHARED-${ownerTag(bob.id)}`;

saveAnalysis({
  id: aliceId, type: 'MODEL', filename: 'm.pth', sha256: sharedSha, fileSizeBytes: 1,
  status: 'NOT DETECTED', riskScore: 10, engine: 'python-full',
  payload: { modelRisk: 10, findings: [] }, findings: [], ownerId: alice.id,
});
saveAnalysis({
  id: bobId, type: 'MODEL', filename: 'm.pth', sha256: sharedSha, fileSizeBytes: 1,
  status: 'DETECTED', riskScore: 90, engine: 'python-full',
  payload: { modelRisk: 90, findings: [critical] }, findings: [critical], ownerId: bob.id,
});

test('the same file analysed by two operators produces two independent rows', () => {
  assert.notEqual(aliceId, bobId);
  assert.equal(listAnalyses(50, 0).length, 2, 'node-wide (no owner) sees both');
});

test('history is scoped to the owning user', () => {
  const aliceList = listAnalyses(50, 0, undefined, alice.id);
  const bobList = listAnalyses(50, 0, undefined, bob.id);
  assert.deepEqual(aliceList.map((a) => a.id), [aliceId]);
  assert.deepEqual(bobList.map((a) => a.id), [bobId]);
});

test('a direct id lookup from the wrong user is a miss, not a leak', () => {
  assert.equal(getAnalysisById(aliceId, bob.id), null, "bob cannot read alice's analysis");
  assert.ok(getAnalysisById(aliceId, alice.id), 'alice can read her own');
});

test('dashboard statistics reflect only the calling user', () => {
  const aliceStats = platformStatistics(alice.id);
  const bobStats = platformStatistics(bob.id);
  assert.equal(aliceStats.modelRisk, 10, "alice's own model risk");
  assert.equal(bobStats.modelRisk, 90, "bob's own model risk");
  assert.equal(aliceStats.criticalFindingsCount, 0, 'alice has no criticals');
  assert.equal(bobStats.criticalFindingsCount, 1, "bob's critical is his alone");
});

test('a passport issued by one user verifies for anyone, but only the issuer can fetch it', () => {
  const analysis = getAnalysisById(aliceId, alice.id)!;
  const passport = buildAibom(analysis, alice.username);
  saveAibom({
    bomId: passport.bomId,
    subjectKind: passport.subject.kind,
    subjectName: passport.subject.filename,
    subjectSha256: passport.subject.sha256,
    status: passport.assurance.status,
    decision: passport.assurance.decision,
    riskScore: passport.assurance.riskScore,
    signingKeyId: passport.seal.signingKeyId,
    sha256: passport.seal.sha256,
    passportJson: JSON.stringify(passport),
    createdBy: alice.username,
    ownerId: alice.id,
  });

  // Cross-user (and cross-node) verification works: it is pure signature + hash-chain.
  const verdict = verifyAibom(passport);
  assert.equal(verdict.status, 'VERIFIED', 'a downloaded passport verifies for the recipient');

  // But the passport lives in alice's workspace only.
  assert.equal(listAiboms(50, bob.id).length, 0, "bob's passport list is empty");
  assert.equal(listAiboms(50, alice.id).length, 1, 'alice sees her issued passport');
  assert.equal(getAibom(passport.bomId, bob.id), null, "bob cannot fetch alice's passport by id");
  assert.ok(getAibom(passport.bomId, alice.id), 'alice can fetch her own');
});

test('tampering with a passport is caught regardless of who verifies it', () => {
  const analysis = getAnalysisById(bobId, bob.id)!;
  const passport = buildAibom(analysis, bob.username) as Record<string, any>;
  // Flip the recorded decision without re-signing.
  passport.assurance.decision = 'ACCEPT';
  const verdict = verifyAibom(passport);
  assert.notEqual(verdict.status, 'VERIFIED', 'an altered passport does not verify');
});
