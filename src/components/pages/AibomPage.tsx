/**
 * AI-BOM -- the model / dataset passport.
 *
 * Three things on one page: issue a signed passport from an existing analysis, verify a
 * passport (including one issued by another node, pasted in), and a list of what has been
 * issued. The verify panel is the point: a passport proves what was assessed and that it
 * has not changed, and anyone can check it offline with nothing but the file.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  BadgeCheck,
  Boxes,
  Database,
  Download,
  FileJson,
  Fingerprint,
  KeyRound,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Stamp,
} from 'lucide-react';
import type { Aibom, AibomSummary, AibomVerifyResult, PlatformStats } from '../../types.js';
import {
  downloadAibom,
  generateAibom,
  listAiboms,
  listAnalyses,
  verifyAibom,
} from '../../api/client.js';
import { useAuth } from '../../context/AuthContext.js';
import { Badge, Button, Card, CardHeader, EmptyState, Hash, SeverityBadge, cn } from '../../ui/primitives.js';
import { LockNote, Stat } from './parts.js';
import type { PageProps } from './shared.js';

const VERIFY_META: Record<
  string,
  { tone: string; ring: string; icon: React.ReactNode }
> = {
  VERIFIED: { tone: 'text-emerald-300', ring: 'ring-emerald-500/30', icon: <ShieldCheck size={24} /> },
  TAMPERED: { tone: 'text-rose-300', ring: 'ring-rose-500/30', icon: <ShieldAlert size={24} /> },
  FORGED: { tone: 'text-fuchsia-300', ring: 'ring-fuchsia-500/30', icon: <KeyRound size={24} /> },
  UNSIGNED: { tone: 'text-amber-300', ring: 'ring-amber-500/30', icon: <ShieldAlert size={24} /> },
  MALFORMED: { tone: 'text-slate-300', ring: 'ring-slate-500/25', icon: <ShieldAlert size={24} /> },
};

export const AibomPage: React.FC<PageProps> = ({ pushToast }) => {
  const { can } = useAuth();
  const [analyses, setAnalyses] = useState<PlatformStats['recentAnalyses']>([]);
  const [selected, setSelected] = useState('');
  const [generating, setGenerating] = useState(false);
  const [passport, setPassport] = useState<Aibom | null>(null);
  const [issued, setIssued] = useState<AibomSummary[]>([]);

  const [pasted, setPasted] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<AibomVerifyResult | null>(null);

  const load = useCallback(async () => {
    try {
      const [a, b] = await Promise.all([
        listAnalyses(40).catch(() => [] as PlatformStats['recentAnalyses']),
        listAiboms(40).catch(() => [] as AibomSummary[]),
      ]);
      // Only completed analyses of a model or dataset can carry a passport.
      setAnalyses(a.filter((x) => x.type === 'MODEL' || x.type === 'DATASET'));
      setIssued(b);
    } catch {
      /* shell handles auth globally */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const generate = async () => {
    if (!selected) return;
    setGenerating(true);
    try {
      const result = await generateAibom(selected);
      setPassport(result);
      pushToast('ok', 'Passport issued', `${result.bomId} · ${result.subject.filename}`);
      await load();
    } catch (error) {
      pushToast('error', 'Could not issue passport', error instanceof Error ? error.message : undefined);
    } finally {
      setGenerating(false);
    }
  };

  const runVerify = async (text?: string) => {
    const source = text ?? pasted;
    let parsed: unknown;
    try {
      parsed = JSON.parse(source);
    } catch {
      pushToast('error', 'Not valid JSON', 'Paste a complete .aibom.json passport.');
      return;
    }
    setVerifying(true);
    try {
      const result = await verifyAibom(parsed);
      setVerifyResult(result);
      pushToast(result.status === 'VERIFIED' ? 'ok' : 'error', `Passport: ${result.status}`, result.detail);
    } catch (error) {
      pushToast('error', 'Verification failed', error instanceof Error ? error.message : undefined);
    } finally {
      setVerifying(false);
    }
  };

  const download = async (bomId: string) => {
    try {
      const name = await downloadAibom(bomId);
      pushToast('ok', 'Passport downloaded', name);
    } catch (error) {
      pushToast('error', 'Download failed', error instanceof Error ? error.message : undefined);
    }
  };

  return (
    <div className="space-y-5">
      <Card className="px-5 py-3.5">
        <span className="mono flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-[var(--color-ink-muted)]">
          <Stamp size={13} className="text-[var(--color-accent-bright)]" />
          A portable, signed record of one artifact's assessment — verifiable offline by anyone, with
          nothing but the file.
        </span>
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Issue */}
        <Card>
          <CardHeader
            title="Issue a passport"
            subtitle="Seal an existing model or dataset analysis into a signed, portable AI-BOM."
            icon={<BadgeCheck size={15} />}
          />
          <div className="space-y-3.5 px-5 pb-5">
            <label className="block">
              <span className="mono mb-1 block text-[9.5px] uppercase tracking-[0.14em] text-[var(--color-ink-dim)]">
                analysed artifact
              </span>
              <select
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                disabled={!can('report:generate')}
                className="mono w-full rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface-0)]/70 px-3 py-2 text-[11.5px] text-[var(--color-ink)] outline-none focus:border-blue-500/60"
              >
                <option value="">select an analysis…</option>
                {analyses.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.type} · {a.name} · {a.status} · risk {a.risk}
                  </option>
                ))}
              </select>
            </label>

            <Button
              variant="primary"
              className="w-full"
              onClick={generate}
              loading={generating}
              disabled={!selected || !can('report:generate')}
              icon={generating ? undefined : <Stamp size={15} />}
            >
              {can('report:generate') ? 'Issue signed passport' : 'Issuing requires an operational role'}
            </Button>

            <LockNote>
              The passport binds the artifact's SHA-256, the verdict, the honest coverage matrix and a
              standards mapping, then seals them with the node's Ed25519 key over RFC 8785
              canonical bytes. Changing any field breaks the seal.
            </LockNote>

            <AnimatePresence>{passport && <PassportView passport={passport} onDownload={download} />}</AnimatePresence>
          </div>
        </Card>

        {/* Verify */}
        <Card>
          <CardHeader
            title="Verify a passport"
            subtitle="Paste any passport — including one issued by another node — to check it here."
            icon={<Fingerprint size={15} />}
          />
          <div className="space-y-3.5 px-5 pb-5">
            <textarea
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              placeholder='Paste a complete .aibom.json passport here…'
              spellCheck={false}
              className="mono h-40 w-full resize-y rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface-0)]/70 p-3 text-[10.5px] leading-relaxed text-[var(--color-ink)] outline-none focus:border-blue-500/60"
            />
            <div className="flex flex-wrap gap-2">
              <Button
                variant="secondary"
                onClick={() => runVerify()}
                loading={verifying}
                disabled={!pasted.trim()}
                icon={verifying ? undefined : <ShieldCheck size={15} />}
              >
                Verify passport
              </Button>
              {passport && (
                <Button
                  onClick={() => {
                    const text = JSON.stringify(passport, null, 2);
                    setPasted(text);
                    void runVerify(text);
                  }}
                >
                  Verify the one just issued
                </Button>
              )}
            </div>

            <AnimatePresence>{verifyResult && <VerifyView result={verifyResult} />}</AnimatePresence>
          </div>
        </Card>
      </div>

      {/* Issued list */}
      <Card>
        <CardHeader
          title="Issued passports"
          subtitle="Every AI-BOM this node has sealed. Append-only."
          icon={<FileJson size={15} />}
          action={
            <button
              onClick={load}
              className="mono flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink)]"
            >
              <RefreshCw size={11} /> refresh
            </button>
          }
        />
        <div className="px-2 pb-3">
          {issued.length === 0 ? (
            <EmptyState icon={<Stamp size={20} />} title="No passports issued yet" description="Issue one from an analysis above." />
          ) : (
            <ul className="space-y-1">
              {issued.map((p) => (
                <li
                  key={p.bomId}
                  className="flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-xl px-3 py-2.5 transition-colors hover:bg-white/[0.03]"
                >
                  <span className="shrink-0 text-[var(--color-ink-dim)]">
                    {p.subjectKind === 'MODEL' ? <Boxes size={14} /> : <Database size={14} />}
                  </span>
                  <span className="mono text-[11px] font-semibold">{p.bomId}</span>
                  <span className="mono max-w-[220px] truncate text-[11px] text-[var(--color-ink-muted)]">
                    {p.subjectName}
                  </span>
                  <Badge tone={p.decision === 'QUARANTINE' ? 'danger' : p.decision === 'REVIEW' ? 'warn' : 'ok'}>
                    {p.decision}
                  </Badge>
                  <span className="flex-1" />
                  <Hash value={p.sha256} chars={12} />
                  <button
                    onClick={() => download(p.bomId)}
                    className="mono flex shrink-0 items-center gap-1 text-[10px] uppercase tracking-wider text-[var(--color-accent-bright)] transition-opacity hover:opacity-70"
                  >
                    <Download size={11} /> .aibom.json
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Card>
    </div>
  );
};

function PassportView({ passport, onDownload }: { passport: Aibom; onDownload: (id: string) => void }) {
  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      className="overflow-hidden"
    >
      <div className="space-y-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/60 p-3.5">
        <div className="flex items-center justify-between gap-2">
          <span className="mono text-[11px] font-semibold">{passport.bomId}</span>
          <Badge
            tone={
              passport.assurance.decision === 'QUARANTINE'
                ? 'danger'
                : passport.assurance.decision === 'REVIEW'
                  ? 'warn'
                  : 'ok'
            }
          >
            {passport.assurance.decision}
          </Badge>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <Stat label="subject" value={passport.subject.filename} />
          <Stat label="kind" value={passport.subject.kind} />
          <Stat label="verdict" value={passport.assurance.status} />
          <Stat label="risk" value={passport.assurance.riskScore} />
        </div>
        <div>
          <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">artifact sha-256</p>
          <p className="mono break-all text-[10px] text-[var(--color-ink-muted)]">{passport.subject.sha256}</p>
        </div>
        <div>
          <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
            seal digest · {passport.seal.canonicalization}
          </p>
          <p className="mono break-all text-[10px] text-emerald-300">{passport.seal.sha256}</p>
        </div>
        <div>
          <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
            signature · {passport.seal.algorithm ?? 'unsigned'}
          </p>
          <p className="mono break-all text-[10px] text-blue-300">
            {passport.seal.signature ?? 'no signing key on this node'}
          </p>
        </div>
        <div>
          <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">issuer fingerprint</p>
          <p className="mono break-all text-[10.5px] text-[var(--color-ink)]">
            {passport.seal.publicKeyFingerprint ?? '—'}
          </p>
        </div>
        {passport.findings.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {passport.findings.slice(0, 6).map((f) => (
              <span key={f.id} className="flex items-center gap-1">
                <SeverityBadge severity={f.severity} />
              </span>
            ))}
          </div>
        )}
        <Button size="sm" onClick={() => onDownload(passport.bomId)} icon={<Download size={13} />}>
          Download .aibom.json
        </Button>
      </div>
    </motion.div>
  );
}

function VerifyView({ result }: { result: AibomVerifyResult }) {
  const meta = VERIFY_META[result.status] ?? VERIFY_META.MALFORMED;
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      className={cn('rounded-xl border p-4 ring-1', meta.ring, 'border-[var(--color-border)] bg-[var(--color-surface-0)]/50')}
    >
      <div className="flex items-start gap-3">
        <span className={cn('grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-[var(--color-surface-0)]/60 ring-1 ring-inset', meta.ring, meta.tone)}>
          {meta.icon}
        </span>
        <div className="min-w-0 flex-1">
          <p className={cn('mono text-lg font-black tracking-tight', meta.tone)}>{result.status}</p>
          <p className="mt-0.5 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">{result.detail}</p>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <Stat label="digest" value={result.digestMatches ? 'matches' : 'mismatch'} tone={result.digestMatches ? 'text-emerald-400' : 'text-rose-400'} />
        <span className="h-8 w-px bg-[var(--color-border)]" />
        <Stat label="signature" value={result.signatureValid ? 'valid' : 'invalid'} tone={result.signatureValid ? 'text-emerald-400' : 'text-rose-400'} />
        <span className="h-8 w-px bg-[var(--color-border)]" />
        <Stat
          label="issuer"
          value={result.issuedByThisNode ? 'this node' : 'external key'}
          tone={result.issuedByThisNode ? 'text-emerald-400' : 'text-amber-400'}
        />
      </div>

      {result.subject && (
        <p className="mono mt-3 text-[10.5px] text-[var(--color-ink-dim)]">
          subject: {result.subject.kind} · {result.subject.filename} · {result.subject.sha256?.slice(0, 16)}…
        </p>
      )}
      {result.issuerFingerprint && (
        <div className="mt-2">
          <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
            issuer fingerprint — confirm this out-of-band
          </p>
          <p className="mono break-all text-[10.5px] text-[var(--color-ink)]">{result.issuerFingerprint}</p>
        </div>
      )}
    </motion.div>
  );
}
