/**
 * Inference provenance: seal a record, then try to defeat the seal.
 *
 * The tamper lab is the point of this page. An analyst seals a record, alters one bound
 * field, and watches verification classify the result. The four outcomes are genuinely
 * different and the page keeps them apart:
 *
 *   VERIFIED  digest and signature both hold
 *   TAMPERED  a bound field changed — the altered fields are named
 *   FORGED    digest matches but the signature does not: someone recomputed the hash
 *             without the key, which a hash-only scheme cannot detect at all
 *   REPLAYED  intact, but the nonce was already consumed
 */

import React, { useCallback, useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  Clock,
  Fingerprint,
  KeyRound,
  Lock,
  RefreshCw,
  Repeat,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import type { InferenceRecord, InferenceVerificationResult, SealedInferenceRecord } from '../../types.js';
import {
  fetchPublicKey,
  listInferenceRecords,
  reverifyStoredRecord,
  sealInference,
  verifyInference,
} from '../../api/client.js';
import { useAuth } from '../../context/AuthContext.js';
import { Badge, Button, Card, CardHeader, EmptyState, Hash, cn } from '../../ui/primitives.js';
import { Stat } from './parts.js';
import type { PageProps } from './shared.js';

const DEFAULT_CONFIG = {
  input_resolution: [224, 224],
  mean_norm: [0.485, 0.456, 0.406],
  std_norm: [0.229, 0.224, 0.225],
  confidence_threshold: 0.5,
};

const STATUS_META: Record<
  string,
  { tone: string; ring: string; icon: React.ReactNode; blurb: string }
> = {
  VERIFIED: {
    tone: 'text-emerald-300',
    ring: 'ring-emerald-500/30',
    icon: <ShieldCheck size={24} />,
    blurb: 'The canonical digest recomputes exactly and the signature verifies.',
  },
  TAMPERED: {
    tone: 'text-rose-300',
    ring: 'ring-rose-500/30',
    icon: <ShieldAlert size={24} />,
    blurb: 'A cryptographically bound field was modified after sealing.',
  },
  FORGED: {
    tone: 'text-fuchsia-300',
    ring: 'ring-fuchsia-500/30',
    icon: <KeyRound size={24} />,
    blurb:
      'The digest matches but the signature does not. The record was re-hashed by a party without the signing key — a digest-only check would have passed this.',
  },
  REPLAYED: {
    tone: 'text-amber-300',
    ring: 'ring-amber-500/30',
    icon: <Repeat size={24} />,
    blurb: 'The record is internally intact but its nonce was already consumed.',
  },
  UNVERIFIABLE: {
    tone: 'text-slate-300',
    ring: 'ring-slate-500/30',
    icon: <ShieldAlert size={24} />,
    blurb: 'Verification could not be completed.',
  },
};

function randomHex(bytes: number): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export const InferencePage: React.FC<PageProps> = ({ onRefresh, pushToast }) => {
  const { can } = useAuth();

  const [inputHash, setInputHash] = useState(() => randomHex(32));
  const [modelIdentifier, setModelIdentifier] = useState('traffic_recon_resnet18.pth');
  const [modelHash, setModelHash] = useState(() => randomHex(32));
  const [prediction, setPrediction] = useState('STOP_SIGN');
  const [confidence, setConfidence] = useState('0.9841');

  const [sealing, setSealing] = useState(false);
  const [sealed, setSealed] = useState<SealedInferenceRecord | null>(null);

  const [tamperPrediction, setTamperPrediction] = useState('');
  const [tamperConfidence, setTamperConfidence] = useState('');
  const [tamperInputHash, setTamperInputHash] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verification, setVerification] = useState<InferenceVerificationResult | null>(null);

  const [records, setRecords] = useState<InferenceRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState(false);
  const [publicKey, setPublicKey] = useState<{ keyId: string; algorithm: string; fingerprint: string } | null>(null);

  const loadRecords = useCallback(async () => {
    setLoadingRecords(true);
    try {
      setRecords(await listInferenceRecords(30));
    } catch {
      // The shell handles an expired session globally.
    } finally {
      setLoadingRecords(false);
    }
  }, []);

  useEffect(() => {
    void loadRecords();
    fetchPublicKey()
      .then((result) => setPublicKey(result.key))
      .catch(() => undefined);
  }, [loadRecords]);

  const seal = async () => {
    setSealing(true);
    setVerification(null);
    try {
      const result = await sealInference({
        inputImageSha256: inputHash.trim().toLowerCase(),
        modelIdentifier: modelIdentifier.trim(),
        modelSha256: modelHash.trim().toLowerCase(),
        inferenceConfig: DEFAULT_CONFIG,
        prediction: prediction.trim(),
        confidence: Number(confidence),
      });
      setSealed(result);
      setTamperPrediction(result.prediction);
      setTamperConfidence(String(result.confidence));
      setTamperInputHash(result.inputImageSha256);
      pushToast('ok', 'Record sealed', `${result.recordId} signed with ${result.signatureAlgorithm ?? 'no key'}`);
      await loadRecords();
      void onRefresh();
    } catch (error) {
      pushToast('error', 'Sealing failed', error instanceof Error ? error.message : undefined);
    } finally {
      setSealing(false);
    }
  };

  const verify = async () => {
    if (!sealed) return;
    setVerifying(true);
    try {
      const result = await verifyInference({
        recordId: sealed.recordId,
        inputImageSha256: tamperInputHash.trim().toLowerCase(),
        modelIdentifier: sealed.modelIdentifier,
        modelSha256: sealed.modelSha256,
        inferenceConfig: sealed.inferenceConfig,
        prediction: tamperPrediction.trim(),
        confidence: Number(tamperConfidence),
        timestampUtc: sealed.timestampUtc,
        nonce: sealed.nonce,
        recordSha256: sealed.recordSha256,
        signature: sealed.signature,
        signingKeyId: sealed.signingKeyId,
      });
      setVerification(result);
      pushToast(result.status === 'VERIFIED' ? 'ok' : 'error', `Verification: ${result.status}`);
      await loadRecords();
      void onRefresh();
    } catch (error) {
      pushToast('error', 'Verification failed', error instanceof Error ? error.message : undefined);
    } finally {
      setVerifying(false);
    }
  };

  const replay = async () => {
    if (!sealed) return;
    try {
      await sealInference({
        inputImageSha256: sealed.inputImageSha256,
        modelIdentifier: sealed.modelIdentifier,
        modelSha256: sealed.modelSha256,
        inferenceConfig: sealed.inferenceConfig,
        prediction: 'SPEED_LIMIT',
        confidence: sealed.confidence,
        nonce: sealed.nonce,
      });
      pushToast('error', 'Replay was accepted', 'This should not happen — the nonce ledger did not fire.');
    } catch (error) {
      pushToast('ok', 'Replay refused', error instanceof Error ? error.message : undefined);
    }
  };

  const reverify = async (recordId: string) => {
    try {
      const result = await reverifyStoredRecord(recordId);
      setVerification(result.recomputed);
      pushToast(
        result.recomputed.status === 'VERIFIED' ? 'ok' : 'error',
        `Stored record ${recordId}: ${result.recomputed.status}`,
        result.recomputed.status === 'VERIFIED' && result.storedStatus !== 'VERIFIED'
          ? `The document on file still hashes to its sealed digest. The stored status reads ${result.storedStatus} because an altered copy was presented earlier.`
          : undefined
      );
    } catch (error) {
      pushToast('error', 'Re-verification failed', error instanceof Error ? error.message : undefined);
    }
  };

  const modified =
    sealed !== null &&
    (tamperPrediction !== sealed.prediction ||
      Number(tamperConfidence) !== sealed.confidence ||
      tamperInputHash !== sealed.inputImageSha256);

  return (
    <div className="space-y-5">
      <Card className="px-5 py-3.5">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <span className="mono flex items-center gap-2 text-[11px] text-[var(--color-ink-muted)]">
            <Lock size={13} className="text-[var(--color-accent-bright)]" />
            RFC 8785 canonicalisation → SHA-256 → Ed25519
          </span>
          {publicKey ? (
            <span className="mono text-[10.5px] text-[var(--color-ink-dim)]">
              node key {publicKey.keyId} · {publicKey.fingerprint}
            </span>
          ) : (
            <Badge tone="warn">no signing key — records hashed but not signed</Badge>
          )}
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="1 · Seal an inference record"
            subtitle="Binds input digest, model digest, preprocessing configuration, prediction, timestamp and a single-use nonce into one canonical document."
            icon={<Fingerprint size={15} />}
          />
          <div className="space-y-3.5 px-5 pb-5">
            <Field label="Input image SHA-256" value={inputHash} onChange={setInputHash} mono
              action={<MiniButton onClick={() => setInputHash(randomHex(32))}>randomise</MiniButton>} />
            <Field label="Model identifier" value={modelIdentifier} onChange={setModelIdentifier} />
            <Field label="Model SHA-256" value={modelHash} onChange={setModelHash} mono
              action={<MiniButton onClick={() => setModelHash(randomHex(32))}>randomise</MiniButton>} />
            <div className="grid grid-cols-2 gap-3.5">
              <Field label="Prediction" value={prediction} onChange={setPrediction} />
              <Field label="Confidence" value={confidence} onChange={setConfidence} mono />
            </div>

            <Button
              variant="primary"
              className="w-full"
              size="lg"
              onClick={seal}
              loading={sealing}
              disabled={!can('inference:seal')}
              icon={sealing ? undefined : <Lock size={16} />}
            >
              {can('inference:seal') ? 'Seal and sign record' : 'Sealing requires an operational role'}
            </Button>

            <AnimatePresence>
              {sealed && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="overflow-hidden"
                >
                  <div className="space-y-2 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/60 p-3.5">
                    <div className="flex items-center justify-between">
                      <span className="mono text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                        record
                      </span>
                      <span className="mono text-[11px] font-semibold">{sealed.recordId}</span>
                    </div>
                    <div>
                      <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">digest</p>
                      <p className="mono break-all text-[10.5px] text-emerald-300">{sealed.recordSha256}</p>
                    </div>
                    <div>
                      <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                        signature · {sealed.signatureAlgorithm ?? 'unsigned'}
                      </p>
                      <p className="mono break-all text-[10.5px] text-blue-300">
                        {sealed.signature ?? sealed.signingError ?? 'not signed'}
                      </p>
                    </div>
                    <details>
                      <summary className="mono cursor-pointer text-[10px] text-[var(--color-ink-dim)] hover:text-[var(--color-ink-muted)]">
                        canonical string
                      </summary>
                      <pre className="mono mt-1.5 max-h-32 overflow-auto whitespace-pre-wrap break-all rounded bg-black/30 p-2 text-[9.5px] text-[var(--color-ink-muted)]">
                        {sealed.canonicalString}
                      </pre>
                    </details>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </Card>

        <Card className={cn(modified && 'ring-1 ring-rose-500/25')}>
          <CardHeader
            title="2 · Tamper lab"
            subtitle="Alter any bound field and re-verify against the original digest."
            icon={<Zap size={15} />}
            action={modified ? <Badge tone="danger">modified</Badge> : undefined}
          />
          <div className="space-y-3.5 px-5 pb-5">
            {!sealed ? (
              <EmptyState
                icon={<Lock size={20} />}
                title="Seal a record first"
                description="The tamper lab verifies an altered payload against a digest that already exists."
              />
            ) : (
              <>
                <Field label="Prediction" value={tamperPrediction} onChange={setTamperPrediction} />
                <div className="grid grid-cols-2 gap-3.5">
                  <Field label="Confidence" value={tamperConfidence} onChange={setTamperConfidence} mono />
                  <div className="flex items-end">
                    <MiniButton
                      onClick={() => {
                        setTamperPrediction(sealed.prediction);
                        setTamperConfidence(String(sealed.confidence));
                        setTamperInputHash(sealed.inputImageSha256);
                      }}
                    >
                      <RotateCcw size={11} /> reset to sealed
                    </MiniButton>
                  </div>
                </div>
                <Field label="Input image SHA-256" value={tamperInputHash} onChange={setTamperInputHash} mono />

                <div className="flex flex-wrap gap-2">
                  <Button size="sm" onClick={() => setTamperPrediction('SPEED_LIMIT')}>
                    intercept: {sealed.prediction} → SPEED_LIMIT
                  </Button>
                  <Button size="sm" onClick={() => setTamperInputHash(randomHex(32))}>
                    substitute input image
                  </Button>
                  <Button size="sm" onClick={replay} icon={<Repeat size={12} />}>
                    replay nonce
                  </Button>
                </div>

                <Button
                  variant="secondary"
                  size="lg"
                  className="w-full"
                  onClick={verify}
                  loading={verifying}
                  disabled={!can('inference:verify')}
                  icon={verifying ? undefined : <ShieldCheck size={16} />}
                >
                  Verify against sealed digest
                </Button>
              </>
            )}
          </div>
        </Card>
      </div>

      <AnimatePresence>
        {verification && <VerdictPanel verification={verification} />}
      </AnimatePresence>

      <Card>
        <CardHeader
          title="Sealed record ledger"
          subtitle={
            'Every record sealed on this node, with the outcome of the most recent verification ' +
            'attempt against it. TAMPERED means a copy that did not match was presented — the ' +
            'stored document is append-only and is never rewritten. Re-verify recomputes the ' +
            'digest from what is on file.'
          }
          icon={<Clock size={15} />}
          action={
            <button
              onClick={loadRecords}
              className="mono flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink)]"
            >
              <RefreshCw size={11} className={loadingRecords ? 'animate-spin' : ''} /> refresh
            </button>
          }
        />
        <div className="px-2 pb-3">
          {records.length === 0 ? (
            <EmptyState icon={<Fingerprint size={20} />} title="No sealed records" description="Seal a record to populate the ledger." />
          ) : (
            <div className="space-y-1">
              {records.map((record) => {
                const ok = record.status === 'VERIFIED';
                return (
                  <div
                    key={record.id}
                    className="flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-xl px-3 py-2.5 transition-colors hover:bg-white/[0.03]"
                  >
                    {ok ? (
                      <ShieldCheck size={14} className="shrink-0 text-emerald-400" />
                    ) : (
                      <ShieldAlert size={14} className="shrink-0 text-rose-400" />
                    )}
                    <span className="mono text-[11px] font-semibold">{record.id}</span>
                    <span className="mono text-[11px] text-[var(--color-ink-muted)]">{record.prediction}</span>
                    <span className="mono text-[10.5px] text-[var(--color-ink-dim)]">
                      {(record.confidence * 100).toFixed(2)}%
                    </span>
                    <Badge tone={ok ? 'ok' : 'danger'}>{record.status}</Badge>
                    <span className="mono text-[10px] text-[var(--color-ink-dim)]">last check</span>
                    {record.signature && <Badge tone="accent">signed</Badge>}
                    {record.isDemo && <Badge tone="warn">eval</Badge>}
                    <span className="flex-1" />
                    <Hash value={record.recordHash} chars={14} />
                    <button
                      onClick={() => reverify(record.id)}
                      className="mono shrink-0 text-[10px] uppercase tracking-wider text-[var(--color-accent-bright)] transition-opacity hover:opacity-70"
                      title="Recompute this record's digest from its stored canonical document"
                    >
                      re-verify
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};

function VerdictPanel({ verification }: { verification: InferenceVerificationResult }) {
  const meta = STATUS_META[verification.status] ?? STATUS_META.UNVERIFIABLE;
  const digestMatches = verification.computedHash === verification.expectedHash;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16, scale: 0.99 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ type: 'spring', stiffness: 260, damping: 26 }}
    >
      <Card className={cn('ring-1', meta.ring)} glow>
        <div className="flex items-start gap-4 p-5">
          <motion.span
            initial={{ scale: 0.7, rotate: -10 }}
            animate={{ scale: 1, rotate: 0 }}
            transition={{ type: 'spring', stiffness: 300, damping: 18 }}
            className={cn('grid h-14 w-14 shrink-0 place-items-center rounded-2xl bg-[var(--color-surface-0)]/60 ring-1 ring-inset', meta.ring, meta.tone)}
          >
            {meta.icon}
          </motion.span>
          <div className="min-w-0 flex-1">
            <p className={cn('mono text-2xl font-black tracking-tight', meta.tone)}>{verification.status}</p>
            <p className="mt-1 text-[12px] leading-relaxed text-[var(--color-ink-muted)]">{meta.blurb}</p>
            <p className="mono mt-1 text-[10px] text-[var(--color-ink-dim)]">
              verified {new Date(verification.verifiedAt).toLocaleString()}
              {verification.recordId ? ` · ${verification.recordId}` : ''}
            </p>
          </div>
        </div>

        <div className="grid gap-4 border-t border-[var(--color-border)] px-5 py-4 md:grid-cols-2">
          <div>
            <p className="mono mb-1 text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
              recorded digest
            </p>
            <p className="mono break-all text-[10.5px] text-[var(--color-ink-muted)]">{verification.expectedHash}</p>
          </div>
          <div>
            <p className="mono mb-1 text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
              recomputed digest
            </p>
            <p className={cn('mono break-all text-[10.5px]', digestMatches ? 'text-emerald-300' : 'text-rose-300')}>
              {verification.computedHash}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 border-t border-[var(--color-border)] px-5 py-3">
          <Stat
            label="digest"
            value={digestMatches ? 'matches' : 'mismatch'}
            tone={digestMatches ? 'text-emerald-400' : 'text-rose-400'}
          />
          <span className="h-8 w-px bg-[var(--color-border)]" />
          <Stat
            label="signature"
            value={
              verification.signatureValid === true
                ? 'valid'
                : verification.signatureValid === false
                  ? 'does not verify'
                  : 'not checked'
            }
            tone={
              verification.signatureValid === true
                ? 'text-emerald-400'
                : verification.signatureValid === false
                  ? 'text-fuchsia-400'
                  : undefined
            }
          />
          {verification.alteredFields.length > 0 && (
            <>
              <span className="h-8 w-px bg-[var(--color-border)]" />
              <div>
                <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                  altered fields
                </p>
                <div className="mt-0.5 flex flex-wrap gap-1">
                  {verification.alteredFields.map((field) => (
                    <Badge key={field} tone="danger">
                      {field}
                    </Badge>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

        {verification.replay && (
          <div className="border-t border-amber-500/25 bg-amber-500/6 px-5 py-3.5">
            <p className="mono mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-amber-300">
              <Repeat size={12} /> {verification.replay.kind}
            </p>
            <p className="text-[11.5px] leading-relaxed text-amber-200/85">{verification.replay.reason}</p>
            {verification.replay.firstSeenAt && (
              <p className="mono mt-1 text-[10px] text-amber-200/60">
                first seen {new Date(verification.replay.firstSeenAt).toLocaleString()} as{' '}
                {verification.replay.originalRecordId}
              </p>
            )}
          </div>
        )}

        {verification.mismatches.length > 0 && (
          <ul className="space-y-1.5 border-t border-[var(--color-border)] px-5 py-4">
            {verification.mismatches.map((mismatch, index) => (
              <li key={index} className="flex gap-2 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                <span className="shrink-0 text-[var(--color-ink-dim)]">→</span>
                <span>{mismatch}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </motion.div>
  );
}

function Field({
  label,
  value,
  onChange,
  mono,
  action,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  mono?: boolean;
  action?: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1 flex items-center justify-between">
        <span className="mono text-[9.5px] uppercase tracking-[0.14em] text-[var(--color-ink-dim)]">{label}</span>
        {action}
      </span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className={cn(
          'w-full rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface-0)]/70 px-3 py-2 text-[12px] text-[var(--color-ink)] outline-none transition-colors',
          'focus:border-blue-500/60 focus:shadow-[0_0_0_3px_rgba(59,130,246,0.1)]',
          mono && 'mono text-[11px]'
        )}
      />
    </label>
  );
}

function MiniButton({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="mono inline-flex items-center gap-1 rounded text-[9.5px] uppercase tracking-wider text-[var(--color-accent-bright)] transition-opacity hover:opacity-70"
    >
      {children}
    </button>
  );
}
