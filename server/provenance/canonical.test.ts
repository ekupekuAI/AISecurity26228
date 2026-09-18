/**
 * Canonicalisation conformance, run against the same vectors as the Python engine.
 *
 * If this file and `ml-engine/tests/test_canonical_vectors.py` do not both pass, records
 * sealed on one side will report TAMPERED on the other, and the integrity system starts
 * producing false alarms -- which is how an integrity system gets turned off.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonical.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(here, 'vectors.json'), 'utf8')) as {
  vectors: Array<{ name: string; input: unknown; canonical: string; sha256: string }>;
};

for (const vector of vectors.vectors) {
  test(`canonicalisation vector: ${vector.name}`, () => {
    assert.equal(canonicalize(vector.input), vector.canonical);
  });

  test(`digest vector: ${vector.name}`, () => {
    // The digest is what gets signed, so it is the value that must agree across the two
    // implementations. Matching the canonical string is only the means to that end.
    const digest = crypto.createHash('sha256').update(canonicalize(vector.input), 'utf8').digest('hex');
    assert.equal(digest, vector.sha256);
  });
}

test('key order in the source object does not change the output', () => {
  const a = { zulu: 1, alpha: { yankee: 2, bravo: 3 }, mike: [1, 2] };
  const b = { mike: [1, 2], alpha: { bravo: 3, yankee: 2 }, zulu: 1 };
  assert.equal(canonicalize(a), canonicalize(b));
});

test('array order is significant', () => {
  assert.notEqual(canonicalize([1, 2, 3]), canonicalize([3, 2, 1]));
});

test('NaN and Infinity are refused rather than coerced', () => {
  assert.throws(() => canonicalize({ v: Number.NaN }), TypeError);
  assert.throws(() => canonicalize({ v: Number.POSITIVE_INFINITY }), TypeError);
  assert.throws(() => canonicalize({ v: Number.NEGATIVE_INFINITY }), TypeError);
});

test('undefined members are omitted, matching JSON.stringify', () => {
  assert.equal(canonicalize({ a: 1, b: undefined }), '{"a":1}');
});

test('BigInt is refused', () => {
  assert.throws(() => canonicalize({ v: 1n }), TypeError);
});

test('a changed value always changes the digest', () => {
  const base = { prediction: 'STOP_SIGN', confidence: 0.9841 };
  const digest = (value: unknown) =>
    crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');

  assert.notEqual(digest(base), digest({ ...base, prediction: 'SPEED_LIMIT' }));
  assert.notEqual(digest(base), digest({ ...base, confidence: 0.9842 }));
});
