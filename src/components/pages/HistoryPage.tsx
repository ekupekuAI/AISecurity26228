/**
 * Audit ledger, analysis history and the signed assurance report.
 *
 * The ledger view exists to be *checked*, not admired. Every block shows the previous
 * hash it claims to extend and the hash it publishes, because that pair is the whole
 * security property: if block N's `previousHash` does not equal block N-1's
 * `currentHash`, the chain is broken and nothing after it can be trusted. The verify
 * button re-walks the chain server-side and reports the first block that fails, rather
 * than a green tick with no provenance.
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Database,
  Download,
  FileText,
  History,
  Link2,
  Link2Off,
  RefreshCw,
  ScrollText,
  ShieldCheck,
} from 'lucide-react';
import type { AssuranceReport, AuditEvent, PlatformStats } from '../../types.js';
import {
  downloadGovernanceReport,
  fetchAuditEvents,
  fetchGovernanceReport,
  listAnalyses,
  verifyAuditChain,
} from '../../api/client.js';
import { useAuth } from '../../context/AuthContext.js';
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  Hash,
  RiskBar,
  SeverityBadge,
  Skeleton,
  cn,
} from '../../ui/primitives.js';
import { LockNote, Stat } from './parts.js';
import type { PageProps } from './shared.js';

type ChainResult = Awaited<ReturnType<typeof verifyAuditChain>>;

const TYPE_TONE: Record<string, string> = {
  DATASET: 'text-violet-300',
  MODEL: 'text-blue-300',
  INFERENCE: 'text-emerald-300',
  DISTRIBUTION: 'text-amber-300',
};

export const HistoryPage: React.FC<PageProps> = ({ pushToast }) => {
  const { can } = useAuth();

  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [analyses, setAnalyses] = useState<PlatformStats['recentAnalyses']>([]);
  const [loading, setLoading] = useState(true);
  const [chain, setChain] = useState<ChainResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [report, setReport] = useState<AssuranceReport | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [eventList, analysisList] = await Promise.all([
        fetchAuditEvents(150).catch(() => [] as AuditEvent[]),
        listAnalyses(60).catch(() => [] as PlatformStats['recentAnalyses']),
      ]);
      setEvents(eventList);
      setAnalyses(analysisList);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const verify = async () => {
    setVerifying(true);
    try {
      const result = await verifyAuditChain();
      setChain(result);
      pushToast(result.valid ? 'ok' : 'error', result.valid ? 'Chain intact' : 'Chain broken', result.details);
    } catch (error) {
      pushToast('error', 'Chain verification failed', error instanceof Error ? error.message : undefined);
    } finally {
      setVerifying(false);
    }
  };

  const buildReport = async () => {
    setLoadingReport(true);
    try {
      setReport(await fetchGovernanceReport());
      pushToast('ok', 'Assurance report generated');
    } catch (error) {
      pushToast('error', 'Report generation failed', error instanceof Error ? error.message : undefined);
    } finally {
      setLoadingReport(false);
    }
  };

  const download = async () => {
    try {
      const filename = await downloadGovernanceReport();
      pushToast('ok', 'Report downloaded', filename);
    } catch (error) {
      pushToast('error', 'Download failed', error instanceof Error ? error.message : undefined);
    }
  };

  /**
   * Link integrity computed client-side.
   *
   * The server's verdict is authoritative; this is the operator being able to see the
   * same property with their own eyes, per block, without trusting the summary line.
   */
  const linkage = useMemo(() => {
    const map = new Map<string, boolean>();
    const ordered = [...events].sort((a, b) => a.sequence - b.sequence);
    ordered.forEach((event, index) => {
      if (index === 0) {
        map.set(event.eventId, true);
        return;
      }
      map.set(event.eventId, ordered[index - 1].currentHash === event.previousHash);
    });
    return map;
  }, [events]);

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Hash-chained audit ledger"
            subtitle="Append-only at the database level: UPDATE and DELETE are refused by trigger, not by convention."
            icon={<ScrollText size={15} />}
            action={
              <Button size="sm" onClick={verify} loading={verifying} icon={<ShieldCheck size={13} />}>
                Verify chain
              </Button>
            }
          />
          <AnimatePresence>
            {chain && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <div
                  className={cn(
                    'mx-5 mb-3 rounded-xl border p-4',
                    chain.valid
                      ? 'border-emerald-500/25 bg-emerald-500/6'
                      : 'border-rose-500/25 bg-rose-500/6'
                  )}
                >
                  <p
                    className={cn(
                      'flex items-center gap-2 text-[13px] font-semibold',
                      chain.valid ? 'text-emerald-300' : 'text-rose-300'
                    )}
                  >
                    {chain.valid ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
                    {chain.valid ? 'Chain verified end to end' : 'Chain integrity failure'}
                  </p>
                  <p className="mt-1.5 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                    {chain.details}
                  </p>
                  <div className="mt-3 grid gap-3 sm:grid-cols-4">
                    <Stat label="blocks" value={chain.chainLength} />
                    <Stat label="verified" value={chain.verifiedBlocks} />
                    <Stat label="signed" value={chain.signedBlocks} />
                    <Stat
                      label="signature failures"
                      value={chain.signatureFailures}
                      tone={chain.signatureFailures > 0 ? 'text-rose-400' : 'text-emerald-400'}
                    />
                  </div>
                  {chain.firstBrokenBlock && (
                    <p className="mono mt-3 rounded-lg bg-rose-500/10 px-3 py-2 text-[10.5px] text-rose-200">
                      first broken block · seq {chain.firstBrokenBlock.sequence} ·{' '}
                      {chain.firstBrokenBlock.eventId} · {chain.firstBrokenBlock.reason}
                    </p>
                  )}
                  <div className="mt-3 grid gap-2 sm:grid-cols-2">
                    <div>
                      <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                        genesis
                      </p>
                      <Hash value={chain.genesisHash} chars={28} />
                    </div>
                    <div>
                      <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                        head
                      </p>
                      <Hash value={chain.headHash} chars={28} />
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="max-h-[560px] overflow-auto px-2 pb-3">
            {loading ? (
              <div className="space-y-2 px-3 py-2">
                {Array.from({ length: 6 }).map((_, index) => (
                  <Skeleton key={index} className="h-12 w-full" />
                ))}
              </div>
            ) : events.length === 0 ? (
              <EmptyState
                icon={<ScrollText size={20} />}
                title="Ledger is empty"
                description="Every analysis, seal, verification and governance decision appends a block here."
              />
            ) : (
              <ul className="space-y-1">
                {events.map((event) => {
                  const linked = linkage.get(event.eventId) !== false;
                  const open = expanded === event.eventId;
                  return (
                    <li key={event.eventId}>
                      <button
                        onClick={() => setExpanded(open ? null : event.eventId)}
                        className="flex w-full items-start gap-3 rounded-xl px-3 py-2.5 text-left transition-colors hover:bg-white/[0.035]"
                      >
                        <span className="mono mt-0.5 w-8 shrink-0 text-right text-[10px] text-[var(--color-ink-dim)]">
                          {event.sequence}
                        </span>
                        <span className="mt-0.5 shrink-0">
                          {linked ? (
                            <Link2 size={13} className="text-emerald-400" />
                          ) : (
                            <Link2Off size={13} className="text-rose-400" />
                          )}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-2">
                            <span className="mono text-[11.5px] font-semibold">{event.eventType}</span>
                            <SeverityBadge severity={event.severity} />
                            {event.signature ? (
                              <Badge tone="accent">signed</Badge>
                            ) : (
                              <Badge tone="warn">unsigned</Badge>
                            )}
                          </span>
                          <span className="mt-0.5 block text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                            {event.description}
                          </span>
                          <span className="mono mt-0.5 block text-[10px] text-[var(--color-ink-dim)]">
                            {event.actor} · {new Date(event.timestamp).toLocaleString()}
                            {event.assetName ? ` · ${event.assetName}` : ''}
                          </span>
                        </span>
                        <ChevronRight
                          size={14}
                          className={cn(
                            'mt-1 shrink-0 text-[var(--color-ink-dim)] transition-transform',
                            open && 'rotate-90'
                          )}
                        />
                      </button>

                      <AnimatePresence>
                        {open && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="overflow-hidden"
                          >
                            <div className="mx-3 mb-2 space-y-2 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/50 p-3.5">
                              <div className="grid gap-2 sm:grid-cols-2">
                                <div>
                                  <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                                    previous hash
                                  </p>
                                  <p className="mono break-all text-[10px] text-[var(--color-ink-muted)]">
                                    {event.previousHash}
                                  </p>
                                </div>
                                <div>
                                  <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                                    this block
                                  </p>
                                  <p
                                    className={cn(
                                      'mono break-all text-[10px]',
                                      linked ? 'text-emerald-300' : 'text-rose-300'
                                    )}
                                  >
                                    {event.currentHash}
                                  </p>
                                </div>
                              </div>
                              {event.assetHash && (
                                <div>
                                  <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                                    asset digest
                                  </p>
                                  <p className="mono break-all text-[10px] text-[var(--color-ink-muted)]">
                                    {event.assetHash}
                                  </p>
                                </div>
                              )}
                              {event.signature && (
                                <div>
                                  <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                                    Ed25519 signature · key {event.signingKeyId}
                                  </p>
                                  <p className="mono break-all text-[10px] text-blue-300">{event.signature}</p>
                                </div>
                              )}
                              {Object.keys(event.metadata ?? {}).length > 0 && (
                                <div>
                                  <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                                    metadata
                                  </p>
                                  <pre className="mono max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-black/30 p-2 text-[9.5px] text-[var(--color-ink-muted)]">
                                    {JSON.stringify(event.metadata, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </Card>

        <div className="space-y-5">
          <Card>
            <CardHeader
              title="Assurance report"
              subtitle="Canonicalised, digested and Ed25519-signed. The seal covers the decision, not just the prose."
              icon={<FileText size={15} />}
            />
            <div className="space-y-3 px-5 pb-5">
              <Button
                variant="primary"
                className="w-full"
                onClick={buildReport}
                loading={loadingReport}
                disabled={!can('report:generate')}
                icon={loadingReport ? undefined : <FileText size={15} />}
              >
                {can('report:generate') ? 'Generate signed report' : 'Report generation not permitted'}
              </Button>
              <Button
                className="w-full"
                onClick={download}
                disabled={!can('report:generate')}
                icon={<Download size={15} />}
              >
                Download plain-text report
              </Button>

              {report && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/60 p-3.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono text-[11px] font-semibold">{report.reportId}</span>
                    <Badge
                      tone={
                        report.decision === 'QUARANTINE'
                          ? 'danger'
                          : report.decision === 'REVIEW'
                            ? 'warn'
                            : 'ok'
                      }
                    >
                      {report.decision}
                    </Badge>
                  </div>
                  <p className="text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                    {report.rationale}
                  </p>
                  <div>
                    <div className="mb-1 flex items-baseline justify-between">
                      <span className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                        composite risk
                      </span>
                      <span className="mono text-[12px] font-semibold">
                        {report.risk.overallRisk.toFixed(1)}
                      </span>
                    </div>
                    <RiskBar value={report.risk.overallRisk} showBands />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <Stat label="findings" value={report.findings.total} />
                    <Stat
                      label="critical"
                      value={report.findings.critical}
                      tone={report.findings.critical > 0 ? 'text-rose-400' : undefined}
                    />
                    <Stat label="trust score" value={report.risk.trustScore.toFixed(1)} />
                    <Stat
                      label="ledger"
                      value={report.auditLedger.valid ? 'valid' : 'broken'}
                      tone={report.auditLedger.valid ? 'text-emerald-400' : 'text-rose-400'}
                    />
                  </div>
                  {report.triggeredRules.length > 0 && (
                    <div>
                      <p className="mono mb-1 text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                        triggered rules
                      </p>
                      <ul className="space-y-1">
                        {report.triggeredRules.map((rule) => (
                          <li key={rule} className="flex gap-1.5 text-[11px] leading-relaxed text-amber-200/85">
                            <span className="shrink-0">→</span>
                            {rule}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div>
                    <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                      report digest · {report.seal.canonicalization}
                    </p>
                    <p className="mono break-all text-[10px] text-emerald-300">{report.seal.sha256}</p>
                  </div>
                  <div>
                    <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                      signature · {report.seal.algorithm ?? 'unsigned'}
                    </p>
                    <p className="mono break-all text-[10px] text-blue-300">
                      {report.seal.signature ?? 'no signing key available on this node'}
                    </p>
                  </div>
                  <p className="text-[10.5px] leading-relaxed text-[var(--color-ink-dim)]">
                    {report.seal.verificationNote}
                  </p>
                </motion.div>
              )}

              <LockNote>
                The report is generated from the ledger and the stored analyses at the moment you
                press the button. It is not cached; two reports taken at different times will differ
                if anything in between changed, and both remain individually verifiable.
              </LockNote>
            </div>
          </Card>
        </div>
      </div>

      <Card>
        <CardHeader
          title="Analysis history"
          subtitle="Every asset submitted to this node, with the engine that produced the verdict."
          icon={<History size={15} />}
          action={
            <button
              onClick={load}
              className="mono flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink)]"
            >
              <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> refresh
            </button>
          }
        />
        <div className="overflow-x-auto px-2 pb-3">
          {analyses.length === 0 ? (
            <EmptyState
              icon={<Database size={20} />}
              title="No analyses recorded"
              description="Submit a dataset or a model and the record will appear here with its digest."
            />
          ) : (
            <table className="w-full min-w-[820px] border-collapse">
              <thead>
                <tr className="border-b border-[var(--color-border)]">
                  {['type', 'asset', 'sha-256', 'risk', 'status', 'findings', 'engine', 'when'].map((head) => (
                    <th
                      key={head}
                      className="mono px-3 py-2 text-left text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]"
                    >
                      {head}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {analyses.map((row) => (
                  <tr
                    key={row.id}
                    className="border-b border-[var(--color-border)]/60 transition-colors last:border-0 hover:bg-white/[0.025]"
                  >
                    <td className={cn('mono px-3 py-2.5 text-[10.5px] font-semibold', TYPE_TONE[row.type])}>
                      {row.type}
                    </td>
                    <td className="max-w-[240px] truncate px-3 py-2.5 text-[12px]" title={row.name}>
                      {row.name}
                      {row.isDemo && <Badge tone="warn" className="ml-2">eval</Badge>}
                    </td>
                    <td className="px-3 py-2.5">
                      <Hash value={row.sha256} chars={12} />
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-2">
                        <span className="mono w-9 text-[11px] font-semibold">{row.risk.toFixed(1)}</span>
                        <RiskBar value={row.risk} className="w-20" />
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <Badge
                        tone={
                          row.status === 'DETECTED'
                            ? 'danger'
                            : row.status === 'SUSPICIOUS'
                              ? 'warn'
                              : row.status === 'NOT DETECTED'
                                ? 'ok'
                                : 'neutral'
                        }
                      >
                        {row.status}
                      </Badge>
                    </td>
                    <td className="mono px-3 py-2.5 text-[11px]">
                      {row.findingCount}
                      {row.criticalCount > 0 && (
                        <span className="ml-1 text-rose-400">({row.criticalCount} crit)</span>
                      )}
                    </td>
                    <td className="mono px-3 py-2.5 text-[10.5px] text-[var(--color-ink-dim)]">
                      {row.engine}
                      {row.analysisMode ? ` · ${row.analysisMode}` : ''}
                      {row.durationSeconds !== null ? ` · ${row.durationSeconds.toFixed(1)}s` : ''}
                    </td>
                    <td className="mono px-3 py-2.5 text-[10.5px] text-[var(--color-ink-dim)]">
                      {new Date(row.timestamp).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
};
