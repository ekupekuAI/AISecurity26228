/**
 * RFC 8785 JSON Canonicalization Scheme -- the TypeScript half.
 *
 * This must produce byte-identical output to `ml-engine/provenance/canonical.py` for
 * every input. If the two drift, a record sealed by one side fails verification on the
 * other and the console reports TAMPERED for a record nobody touched -- the fastest way
 * to make operators stop trusting an integrity tool. `server/provenance/canonical.test.ts`
 * pins the shared vectors.
 *
 * JavaScript happens to fit JCS almost exactly, which is not a coincidence: the spec is
 * built on ECMAScript's own serialisation rules.
 *
 *  - `JSON.stringify` on a number *is* `Number::toString`, which is what the spec cites.
 *  - `JSON.stringify` on a string produces exactly the spec's minimal escaping: short
 *    forms for the five named controls, `\u00xx` for the rest, non-ASCII left as UTF-8.
 *  - `Array.prototype.sort()` with no comparator orders by UTF-16 code unit, which is
 *    the spec's key ordering.
 *
 * So the work here is structural: sort keys, emit no whitespace, and refuse the values
 * JSON cannot represent rather than silently coercing them.
 */

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export function canonicalize(value: unknown): string {
  if (value === null) return 'null';

  const type = typeof value;

  if (type === 'boolean') return value ? 'true' : 'false';

  if (type === 'number') {
    const numeric = value as number;
    if (!Number.isFinite(numeric)) {
      // RFC 8785 section 3.2.2.3: NaN and Infinity have no JSON representation. Coercing
      // them to null would let two different records share a digest.
      throw new TypeError('NaN and Infinity cannot be canonicalised');
    }
    return JSON.stringify(numeric);
  }

  if (type === 'string') return JSON.stringify(value);

  if (type === 'bigint') {
    throw new TypeError('BigInt cannot be canonicalised: it has no JSON number representation');
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  }

  if (type === 'object') {
    const record = value as Record<string, unknown>;
    // Default sort is UTF-16 code unit order, which is what the spec requires.
    const keys = Object.keys(record).sort();
    const parts: string[] = [];
    for (const key of keys) {
      const inner = record[key];
      // Match JSON.stringify: an undefined member is omitted, not encoded as null.
      if (inner === undefined) continue;
      parts.push(`${JSON.stringify(key)}:${canonicalize(inner)}`);
    }
    return `{${parts.join(',')}}`;
  }

  throw new TypeError(`${type} is not JSON-serialisable and cannot be canonicalised`);
}

export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}
