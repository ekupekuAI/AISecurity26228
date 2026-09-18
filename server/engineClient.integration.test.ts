/**
 * Gateway <-> engine HTTP integration.
 *
 * Exercises the one seam the unit tests cannot: the real multipart request the gateway
 * builds, parsed by the engine's hand-rolled multipart reader, analysed by the real
 * detectors, and returned as JSON. Skips cleanly when the engine is not running, so it is
 * safe in `npm test`; run the engine (`npm run ml`) to execute it for real.
 *
 * The malicious checkpoint is the sharpest end-to-end assertion available: the engine must
 * report it MALICIOUS and risk 100 without ever deserialising it.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-integ-test-'));
process.env.AIA_DATA_DIR = scratch;

const { checkEngineHealth, analyzeModelRemote, analyzeDatasetRemote } = await import('./engineClient.js');

const ASSETS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'demo-assets');

const health = await checkEngineHealth(true).catch(() => null);
const engineUp = health?.status === 'ONLINE';

test('malicious checkpoint is reported MALICIOUS / risk 100 over the real HTTP seam', { skip: !engineUp ? 'engine not running' : false }, async () => {
  const file = path.join(ASSETS, 'malicious_model.pth');
  if (!fs.existsSync(file)) return; // corpus not generated
  const result = await analyzeModelRemote('malicious_model.pth', fs.readFileSync(file));

  assert.equal(result.status, 'DETECTED');
  assert.equal(Number(result.modelRisk), 100);
  assert.equal(result.engine, 'python-full');
  assert.equal((result.pickleAudit as Record<string, unknown> | null)?.verdict, 'MALICIOUS');
});

test('a clean corpus returns a real analysis with findings array over HTTP', { skip: !engineUp ? 'engine not running' : false }, async () => {
  const file = path.join(ASSETS, 'clean_corpus.zip');
  if (!fs.existsSync(file)) return;
  const result = await analyzeDatasetRemote('clean_corpus.zip', fs.readFileSync(file));

  assert.equal(result.engine, 'python-full');
  assert.ok(Array.isArray(result.findings));
  assert.equal(typeof result.datasetRisk, 'number');
  assert.ok(Number(result.totalSamples) > 0);
});
