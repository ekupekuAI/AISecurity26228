/**
 * AI-BOM signed-passport verification.
 *
 * A passport is a portable, offline-verifiable claim about one artifact. The tests prove the
 * full seal lifecycle: a freshly built passport verifies and is attributed to this node, a
 * field altered after sealing reads TAMPERED, a stripped signature reads UNSIGNED, and a
 * non-document reads MALFORMED. This is the same fail-closed contract as the audit ledger,
 * applied to a document that leaves the node.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-aibom-test-'));
process.env.AIA_DATA_DIR = scratch;

const { buildAibom, verifyAibom, attestationsFor } = await import('./aibom.js');

const analysis = (over: Record<string, unknown> = {}) => ({
  filename: 'traffic_resnet18.pth',
  sha256: 'a'.repeat(64),
  fileSizeBytes: 44_000_000,
  modelRisk: 5,
  status: 'NOT DETECTED',
  engine: 'python-full',
  framework: 'PyTorch',
  architecture: 'ResNet-18',
  analysisMode: 'WHITE_BOX',
  backdoorConfidence: 0,
  findings: [] as Array<Record<string, unknown>>,
  coverage: [] as Array<Record<string, unknown>>,
  ...over,
});

test('a freshly built passport verifies and is attributed to this node', () => {
  const bom = buildAibom(analysis(), 'assurance.lead');
  const v = verifyAibom(bom);
  assert.equal(v.status, 'VERIFIED');
  assert.equal(v.digestMatches, true);
  assert.equal(v.signatureValid, true);
  assert.equal(v.issuedByThisNode, true);
  assert.equal(v.subject?.sha256, 'a'.repeat(64));
});

test('a field altered after sealing reads TAMPERED', () => {
  const bom = buildAibom(analysis({ modelRisk: 100, status: 'DETECTED', findings: [{ findingId: 'SEC-MALICIOUS-PICKLE-OPCODE', severity: 'CRITICAL' }] }), 'assurance.lead');
  assert.equal(verifyAibom(bom).status, 'VERIFIED'); // sanity: it starts valid

  const forged = JSON.parse(JSON.stringify(bom));
  forged.assurance.decision = 'ACCEPT';
  forged.assurance.riskScore = 0;
  const v = verifyAibom(forged);
  assert.equal(v.status, 'TAMPERED');
  assert.equal(v.digestMatches, false);
});

test('a passport with its signature stripped reads UNSIGNED', () => {
  const bom = buildAibom(analysis(), 'assurance.lead');
  const copy = JSON.parse(JSON.stringify(bom));
  copy.seal.signature = null;
  assert.equal(verifyAibom(copy).status, 'UNSIGNED');
});

test('a non-document reads MALFORMED', () => {
  assert.equal(verifyAibom('not a passport').status, 'MALFORMED');
  assert.equal(verifyAibom(null).status, 'MALFORMED');
  assert.equal(verifyAibom({ nope: true }).status, 'MALFORMED');
});

test('a malicious-serialization finding maps to the ATLAS/CWE controls', () => {
  const a = attestationsFor([{ findingId: 'SEC-MALICIOUS-PICKLE-OPCODE', category: 'SUPPLY_CHAIN' }]);
  assert.ok(a.mitreAtlas.some((s) => s.includes('AML.T0010')));
  assert.ok(a.cwe.some((s) => s.includes('CWE-502')));
});
