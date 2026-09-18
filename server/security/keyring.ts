/**
 * Ed25519 keyring, shared byte-for-byte with the Python engine.
 *
 * Both processes read the same `data/keys/signing_keys.json`, so a record sealed by
 * either can be verified by the other. Node owns creation only when the file is absent,
 * which keeps a single authoritative key per node rather than two that disagree.
 *
 * Signatures are domain-separated: every message is prefixed with a context string and a
 * NUL byte, so a signature over an inference record can never be presented as a
 * signature over an audit block. Without that, any two structures that can be made to
 * share bytes become interchangeable under the same key.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { CONFIG } from '../config.js';
import { log } from '../logger.js';
import { canonicalBytes } from '../provenance/canonical.js';

export const DOMAIN_INFERENCE = Buffer.from('AIA-v1:inference-record', 'utf8');
export const DOMAIN_AUDIT = Buffer.from('AIA-v1:audit-block', 'utf8');
export const DOMAIN_REPORT = Buffer.from('AIA-v1:assurance-report', 'utf8');
// AI-BOM passports. 'AIA-v1' is the crypto protocol namespace, not the display brand,
// so it stays fixed -- changing it would invalidate every signature already issued.
export const DOMAIN_AIBOM = Buffer.from('AIA-v1:ai-bom', 'utf8');

const KEY_PATH = path.join(CONFIG.dataDir, 'keys', 'signing_keys.json');

interface StoredKeyring {
  version: number;
  active: {
    keyId: string;
    algorithm: string;
    privateKeyPem: string;
    publicKeyPem: string;
    createdAt: string;
  };
  retired: Array<{ keyId: string; publicKeyPem: string; retiredAt: string }>;
}

export interface PublicKeyInfo {
  keyId: string;
  algorithm: 'Ed25519';
  publicKey: string;
  fingerprint: string;
  createdAt: string;
  active: boolean;
}

class Keyring {
  private privateKey: crypto.KeyObject | null = null;
  private publicKey: crypto.KeyObject | null = null;
  private retired = new Map<string, crypto.KeyObject>();
  private keyId = '';
  private createdAt = '';
  private failure: string | null = null;

  constructor() {
    try {
      this.load();
    } catch (error) {
      this.failure = error instanceof Error ? error.message : String(error);
      log.error('keyring unavailable', { reason: this.failure });
    }
  }

  private load(): void {
    fs.mkdirSync(path.dirname(KEY_PATH), { recursive: true, mode: 0o700 });

    if (fs.existsSync(KEY_PATH)) {
      const stored = JSON.parse(fs.readFileSync(KEY_PATH, 'utf8')) as StoredKeyring;
      this.privateKey = crypto.createPrivateKey(stored.active.privateKeyPem);
      this.publicKey = crypto.createPublicKey(stored.active.publicKeyPem);
      this.keyId = stored.active.keyId;
      this.createdAt = stored.active.createdAt;
      for (const entry of stored.retired ?? []) {
        this.retired.set(entry.keyId, crypto.createPublicKey(entry.publicKeyPem));
      }
      return;
    }

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.createdAt = new Date().toISOString();
    this.keyId = `AIA-${crypto.createHash('sha256').update(this.rawPublicKey()).digest('hex').slice(0, 16).toUpperCase()}`;

    const document: StoredKeyring = {
      version: 1,
      active: {
        keyId: this.keyId,
        algorithm: 'Ed25519',
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        createdAt: this.createdAt,
      },
      retired: [],
    };

    // Mode is applied at creation so the private key is never briefly world-readable.
    fs.writeFileSync(KEY_PATH, JSON.stringify(document, null, 2), { mode: 0o600, flag: 'w' });
    try {
      fs.chmodSync(KEY_PATH, 0o600);
    } catch {
      // Windows ignores POSIX modes; the directory ACL applies.
    }
    log.info('generated node signing key', { keyId: this.keyId });
  }

  private rawPublicKey(): Buffer {
    if (!this.publicKey) return Buffer.alloc(0);
    // SPKI DER for Ed25519 is a fixed 12-byte prefix followed by the 32-byte key.
    const der = this.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    return der.subarray(der.length - 32);
  }

  get available(): boolean {
    return this.privateKey !== null;
  }

  get error(): string | null {
    return this.failure;
  }

  get id(): string {
    return this.keyId;
  }

  publicKeyInfo(): PublicKeyInfo | null {
    if (!this.publicKey) return null;
    const raw = this.rawPublicKey();
    const digest = crypto.createHash('sha256').update(raw).digest('hex').toUpperCase();
    return {
      keyId: this.keyId,
      algorithm: 'Ed25519',
      publicKey: raw.toString('base64'),
      fingerprint: (digest.match(/.{1,4}/g) ?? []).slice(0, 8).join(':'),
      createdAt: this.createdAt,
      active: true,
    };
  }

  sign(payload: Buffer, domain: Buffer = DOMAIN_INFERENCE): { signature: string; keyId: string } | null {
    if (!this.privateKey) return null;
    const message = Buffer.concat([domain, Buffer.from([0]), payload]);
    // Ed25519 takes a null algorithm: the hash is part of the scheme.
    const signature = crypto.sign(null, message, this.privateKey);
    return { signature: signature.toString('base64'), keyId: this.keyId };
  }

  verify(payload: Buffer, signatureB64: string, keyId?: string | null, domain: Buffer = DOMAIN_INFERENCE): boolean {
    if (!this.publicKey) return false;
    let signature: Buffer;
    try {
      signature = Buffer.from(signatureB64, 'base64');
      if (signature.length !== 64) return false;
    } catch {
      return false;
    }

    const message = Buffer.concat([domain, Buffer.from([0]), payload]);
    const candidates: crypto.KeyObject[] = [];
    if (!keyId || keyId === this.keyId) candidates.push(this.publicKey);
    if (keyId && this.retired.has(keyId)) candidates.push(this.retired.get(keyId)!);
    if (candidates.length === 0) candidates.push(this.publicKey, ...this.retired.values());

    for (const key of candidates) {
      try {
        if (crypto.verify(null, message, key, signature)) return true;
      } catch {
        // A malformed key or signature is a verification failure, not an error to raise.
      }
    }
    return false;
  }

  signDocument(document: unknown, domain: Buffer = DOMAIN_INFERENCE): {
    digest: string;
    signature: string | null;
    keyId: string | null;
    canonical: string;
  } {
    const payload = canonicalBytes(document);
    const digest = crypto.createHash('sha256').update(payload).digest('hex');
    const signed = this.sign(payload, domain);
    return {
      digest,
      signature: signed?.signature ?? null,
      keyId: signed?.keyId ?? null,
      canonical: payload.toString('utf8'),
    };
  }
}

let instance: Keyring | null = null;

export function getKeyring(): Keyring {
  if (!instance) instance = new Keyring();
  return instance;
}

export type { Keyring };
