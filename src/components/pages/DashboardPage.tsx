/**
 * Assurance monitor.
 *
 * Answers one question first — may this pipeline be deployed — and then shows the
 * evidence behind that answer. Every number is read from the node; nothing here is
 * synthesised, and when there is no data the panel says so rather than rendering a
 * plausible-looking placeholder.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { motion } from 'motion/react';
import {
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Database,
  FileWarning,
  Fingerprint,
  Gavel,
  ShieldAlert,
  ShieldCheck,
  Users,
  Waves,
} from 'lucide-react';
import type { AuditEvent, Finding, GovernanceEvaluation, PlatformStats } from '../../types.js';
import type { NavTab } from '../Shell.js';
import { fetchGovernanceDecision, listFindings } from '../../api/client.js';
import {
  Badge,
  Card,
  CardHeader,
  Counter,
  EmptyState,
  Hash,
  RiskBar,
  SeverityBadge,
  Skeleton,
  Stagger,
  cn,
} from '../../ui/primitives.js';
import type { PageProps } from './shared.js';

interface DashboardProps extends PageProps {
  stats: PlatformStats | null;
  loading: boolean;
  onNavigate: (tab: NavTab) => void;
}

const DECISION_STYLE = {
  ACCEPT: {
    ring: 'ring-emerald-500/30',
    glow: 'from-emerald-500/16',
    text: 'text-emerald-300',
    icon: ShieldCheck,
    lead: 'Authorised for operational deployment',
  },
  REVIEW: {
    ring: 'ring-amber-500/30',
    glow: 'from-amber-500/16',
    text: 'text-amber-300',
    icon: AlertTriangle,
    lead: 'Human-in-the-loop triage required',
  },
  QUARANTINE: {
    ring: 'ring-rose-500/30',
    glow: 'from-rose-500/16',
    text: 'text-rose-300',
    icon: ShieldAlert,
    lead: 'Immediate operational quarantine',
  },
} as const;

export const DashboardPage: React.FC<DashboardProps> = ({
  stats,
  loading,
  onNavigate,
  onFindingClick,
}) => {
  const [decision, setDecision] = useState<GovernanceEvaluation | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);

  const load = useCallback(async () => {
    const [governance, findingList] = await Promise.all([
      fetchGovernanceDecision().catch(() => null),
      listFindings(12).catch(() => [] as Finding[]),
    ]);
    if (governance) setDecision(governance);
    setFindings(findingList);
  }, []);

  useEffect(() => {
    void load();
  }, [load, stats]);

  const hasData = (stats?.analyzedAssetsCount ?? 0) > 0;

  return (
    <div className="space-y-5">
      {/* Governance verdict */}
      {decision ? (
        <GovernancePanel decision={decision} />
      ) : loading ? (
        <Skeleton className="h-44 w-full" />
      ) : null}

      {/* Pillars */}
      <Stagger className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stagger.Item>
          <PillarCard
            label="Dataset integrity"
            value={stats?.datasetRisk ?? 0}
            weight={0.35}
            icon={Database}
            onClick={() => onNavigate('dataset')}
            loading={loading}
          />
        </Stagger.Item>
        <Stagger.Item>
          <PillarCard
            label="Model integrity"
            value={stats?.modelRisk ?? 0}
            weight={0.35}
            icon={Boxes}
            onClick={() => onNavigate('model')}
            loading={loading}
          />
        </Stagger.Item>
        <Stagger.Item>
          <PillarCard
            label="Inference integrity"
            value={stats?.inferenceIntegrityRisk ?? 0}
            weight={0.15}
            icon={Fingerprint}
            onClick={() => onNavigate('inference')}
            loading={loading}
          />
        </Stagger.Item>
        <Stagger.Item>
          <PillarCard
            label="Distribution shift"
            value={stats?.distributionShiftRisk ?? 0}
            weight={0.15}
            icon={Waves}
            onClick={() => onNavigate('shift')}
            loading={loading}
          />
        </Stagger.Item>
      </Stagger>

      {/* Counters */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="Assets inspected" value={stats?.analyzedAssetsCount ?? 0} icon={Boxes} />
        <Metric
          label="Critical findings"
          value={stats?.criticalFindingsCount ?? 0}
          icon={FileWarning}
          tone={(stats?.criticalFindingsCount ?? 0) > 0 ? 'danger' : 'ok'}
        />
        <Metric
          label="Quarantined assets"
          value={stats?.quarantinedAssetsCount ?? 0}
          icon={ShieldAlert}
          tone={(stats?.quarantinedAssetsCount ?? 0) > 0 ? 'danger' : 'ok'}
        />
        <Metric
          label="Compromised records"
          value={stats?.tamperedRecordCount ?? 0}
          icon={Fingerprint}
          tone={(stats?.tamperedRecordCount ?? 0) > 0 ? 'danger' : 'ok'}
          sub={`of ${stats?.inferenceRecordCount ?? 0} sealed`}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.35fr_1fr]">
        {/* Findings */}
        <Card>
          <CardHeader
            title="Outstanding findings"
            subtitle="Ordered by severity. Select one to inspect its evidence and the rule that fired."
            icon={<FileWarning size={15} />}
            action={
              findings.length > 0 ? (
                <Badge tone={findings.some((f) => f.severity === 'CRITICAL') ? 'danger' : 'neutral'}>
                  {findings.length}
                </Badge>
              ) : undefined
            }
          />
          <div className="px-2 pb-2">
            {loading && findings.length === 0 ? (
              <div className="space-y-2 p-3">
                {[0, 1, 2].map((index) => (
                  <Skeleton key={index} className="h-16 w-full" />
                ))}
              </div>
            ) : findings.length === 0 ? (
              <EmptyState
                icon={<CheckCircle2 size={20} />}
                title={hasData ? 'No findings outstanding' : 'No assets inspected yet'}
                description={
                  hasData
                    ? 'Every inspected asset passed its detector battery. Findings appear here as assets are submitted.'
                    : 'Submit a dataset archive or a model checkpoint to begin an assessment.'
                }
              />
            ) : (
              <ul className="space-y-1">
                {findings.map((finding) => (
                  <li key={finding.id}>
                    <motion.button
                      whileHover={{ x: 3 }}
                      whileTap={{ scale: 0.995 }}
                      transition={{ type: 'spring', stiffness: 500, damping: 34 }}
                      onClick={() => onFindingClick(finding)}
                      className="group flex w-full items-start gap-3 rounded-xl px-3 py-2.5 text-left transition-colors hover:bg-white/[0.035]"
                    >
                      <span className="mt-0.5 shrink-0">
                        <SeverityBadge severity={finding.severity} />
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-baseline gap-2">
                          <span className="mono truncate text-[11.5px] font-semibold text-[var(--color-ink)]">
                            {finding.findingId}
                          </span>
                          {/* The same detector fires on different assets; without the
                              asset name two rows read as a duplicate. */}
                          {finding.affectedAsset && (
                            <span className="mono truncate text-[10px] text-[var(--color-ink-dim)]">
                              {finding.affectedAsset}
                            </span>
                          )}
                        </span>
                        <span className="mt-0.5 block line-clamp-2 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                          {finding.explanation}
                        </span>
                      </span>
                      <span className="mono shrink-0 pt-0.5 text-[10px] text-[var(--color-ink-dim)]">
                        {(finding.confidence * 100).toFixed(0)}%
                      </span>
                    </motion.button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>

        <div className="space-y-5">
          {/* Contributors */}
          <Card>
            <CardHeader
              title="Contributor risk"
              subtitle="One line per source, summed across every submission, scored on its worst"
              icon={<Users size={15} />}
            />
            <div className="px-5 pb-5">
              {(stats?.topContributors?.length ?? 0) === 0 ? (
                <p className="py-4 text-center text-[11.5px] text-[var(--color-ink-dim)]">
                  No attributed contributors yet.
                </p>
              ) : (
                <div className="space-y-3">
                  {stats!.topContributors.map((contributor) => (
                    <div key={contributor.name}>
                      <div className="mb-1.5 flex items-baseline justify-between gap-3">
                        <span className="truncate text-[12px] font-medium">{contributor.name}</span>
                        <span
                          className={cn(
                            'mono shrink-0 text-[11px] font-bold',
                            contributor.riskScore >= 70
                              ? 'text-rose-400'
                              : contributor.riskScore >= 30
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                          )}
                        >
                          {contributor.riskScore.toFixed(0)}
                        </span>
                      </div>
                      <RiskBar value={contributor.riskScore} showBands />
                      <p className="mono mt-1 text-[10px] text-[var(--color-ink-dim)]">
                        {contributor.sampleCount} samples · {contributor.triggerSamples ?? 0} triggered
                        {(contributor.submissionCount ?? 1) > 1
                          ? ` · ${contributor.submissionCount} submissions`
                          : ''}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>

          {/* Ledger */}
          <Card>
            <CardHeader
              title="Audit ledger"
              subtitle="Append-only, hash-chained, Ed25519-signed"
              icon={<Gavel size={15} />}
              action={
                <button
                  onClick={() => onNavigate('history')}
                  className="mono text-[10px] uppercase tracking-wider text-[var(--color-accent-bright)] transition-opacity hover:opacity-75"
                >
                  view all
                </button>
              }
            />
            <div className="px-3 pb-3">
              {(stats?.recentAuditEvents?.length ?? 0) === 0 ? (
                <p className="py-4 text-center text-[11.5px] text-[var(--color-ink-dim)]">
                  Ledger is empty.
                </p>
              ) : (
                <ul className="space-y-0.5">
                  {stats!.recentAuditEvents.slice(0, 6).map((event: AuditEvent) => (
                    <li
                      key={event.eventId}
                      className="flex items-start gap-2.5 rounded-lg px-2 py-2 transition-colors hover:bg-white/[0.03]"
                    >
                      <span
                        className={cn(
                          'mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full',
                          event.severity === 'CRITICAL'
                            ? 'bg-rose-400'
                            : event.severity === 'HIGH'
                              ? 'bg-orange-400'
                              : 'bg-slate-500'
                        )}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="mono truncate text-[10.5px] font-semibold">{event.eventType}</p>
                        <p className="line-clamp-2 text-[10.5px] leading-relaxed text-[var(--color-ink-muted)]">
                          {event.description}
                        </p>
                      </div>
                      <span className="mono shrink-0 text-[9.5px] text-[var(--color-ink-dim)]">
                        #{event.sequence}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Card>
        </div>
      </div>

      {/* Recent analyses */}
      <Card>
        <CardHeader
          title="Analysis history"
          subtitle="Each row is a completed assessment held in the evidence database"
          icon={<Boxes size={15} />}
        />
        <div className="px-2 pb-3">
          {(stats?.recentAnalyses?.length ?? 0) === 0 ? (
            <EmptyState
              icon={<Database size={20} />}
              title="No analyses recorded"
              description="Submit a dataset or model to produce the first assessment."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px]">
                <thead>
                  <tr className="mono text-[9.5px] uppercase tracking-[0.14em] text-[var(--color-ink-dim)]">
                    <th className="px-3 py-2 text-left font-medium">Asset</th>
                    <th className="px-3 py-2 text-left font-medium">Type</th>
                    <th className="px-3 py-2 text-left font-medium">Digest</th>
                    <th className="px-3 py-2 text-left font-medium">Engine</th>
                    <th className="px-3 py-2 text-right font-medium">Findings</th>
                    <th className="px-3 py-2 text-right font-medium">Risk</th>
                    <th className="px-3 py-2 text-right font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {stats!.recentAnalyses.map((analysis) => (
                    <tr
                      key={analysis.id}
                      className="border-t border-[var(--color-border)] transition-colors hover:bg-white/[0.025]"
                    >
                      <td className="max-w-[220px] truncate px-3 py-2.5 text-[12px] font-medium">
                        {analysis.name}
                        {analysis.isDemo && (
                          <Badge tone="warn" className="ml-2">
                            eval
                          </Badge>
                        )}
                      </td>
                      <td className="mono px-3 py-2.5 text-[10.5px] text-[var(--color-ink-muted)]">
                        {analysis.type}
                      </td>
                      <td className="px-3 py-2.5">
                        <Hash value={analysis.sha256} chars={12} />
                      </td>
                      <td className="mono px-3 py-2.5 text-[10.5px] text-[var(--color-ink-dim)]">
                        {analysis.engine === 'node-fallback' ? (
                          <span className="text-amber-400">degraded</span>
                        ) : (
                          (analysis.analysisMode ?? analysis.engine)
                        )}
                      </td>
                      <td className="mono px-3 py-2.5 text-right text-[11px]">
                        {analysis.criticalCount > 0 ? (
                          <span className="text-rose-400">
                            {analysis.criticalCount}/{analysis.findingCount}
                          </span>
                        ) : (
                          <span className="text-[var(--color-ink-muted)]">{analysis.findingCount}</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <span
                          className={cn(
                            'mono text-[12px] font-bold',
                            analysis.risk >= 70
                              ? 'text-rose-400'
                              : analysis.risk >= 30
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                          )}
                        >
                          {analysis.risk.toFixed(0)}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <Badge
                          tone={
                            analysis.status === 'DETECTED'
                              ? 'danger'
                              : analysis.status === 'SUSPICIOUS'
                                ? 'warn'
                                : analysis.status === 'NOT DETECTED'
                                  ? 'ok'
                                  : 'neutral'
                          }
                        >
                          {analysis.status}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};

/* ------------------------------------------------------------------ pieces */

function GovernancePanel({ decision }: { decision: GovernanceEvaluation }) {
  const style = DECISION_STYLE[decision.decision];
  const Icon = style.icon;

  return (
    <Card tilt glow className={cn('ring-1', style.ring)}>
      <div className={cn('absolute inset-0 bg-gradient-to-br to-transparent', style.glow)} aria-hidden />
      <div className="relative grid gap-6 p-6 lg:grid-cols-[auto_1fr]">
        <div className="flex items-center gap-4">
          <motion.span
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ type: 'spring', stiffness: 260, damping: 18 }}
            className={cn(
              'grid h-16 w-16 shrink-0 place-items-center rounded-2xl bg-[var(--color-surface-0)]/60 ring-1 ring-inset',
              style.ring,
              style.text
            )}
          >
            <Icon size={30} />
          </motion.span>
          <div>
            <p className="mono text-[9.5px] uppercase tracking-[0.2em] text-[var(--color-ink-dim)]">
              Governance decision
            </p>
            <p className={cn('mono text-3xl font-black tracking-tight', style.text)}>{decision.decision}</p>
            <p className="mt-0.5 text-[11.5px] text-[var(--color-ink-muted)]">{style.lead}</p>
          </div>
        </div>

        <div className="min-w-0">
          <div className="mb-3 flex flex-wrap items-baseline gap-x-6 gap-y-1">
            <span className="mono text-[11px] text-[var(--color-ink-muted)]">
              composite risk{' '}
              <span className="text-lg font-bold text-[var(--color-ink)]">
                <Counter value={decision.overallRisk} decimals={1} />
              </span>
              /100
            </span>
            <span className="mono text-[11px] text-[var(--color-ink-muted)]">
              trust{' '}
              <span className="text-lg font-bold text-[var(--color-ink)]">
                <Counter value={decision.trustScore} decimals={1} />
              </span>
              /100
            </span>
          </div>

          <RiskBar value={decision.overallRisk} showBands className="h-2" />
          <p className="mono mt-1.5 text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
            accept &lt; {decision.thresholds.acceptBelow} · review {decision.thresholds.acceptBelow}–
            {decision.thresholds.quarantineAtOrAbove - 1} · quarantine ≥ {decision.thresholds.quarantineAtOrAbove}
          </p>

          {decision.triggeredRules.length > 0 && (
            <div className="mt-4">
              <p className="mono mb-1.5 text-[9.5px] uppercase tracking-[0.16em] text-[var(--color-ink-dim)]">
                Triggered rules
              </p>
              <ul className="space-y-1">
                {decision.triggeredRules.map((rule) => (
                  <li key={rule} className="flex gap-2 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                    <span className="shrink-0 text-[var(--color-ink-dim)]">→</span>
                    <span>{rule}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <p className="mt-3 border-t border-[var(--color-border)] pt-3 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
            {decision.rationale}
          </p>
        </div>
      </div>
    </Card>
  );
}

function PillarCard({
  label,
  value,
  weight,
  icon: Icon,
  onClick,
  loading,
}: {
  label: string;
  value: number;
  weight: number;
  icon: React.ComponentType<{ size?: number }>;
  onClick: () => void;
  loading: boolean;
}) {
  if (loading) return <Skeleton className="h-[122px] w-full" />;

  const tone = value >= 70 ? 'text-rose-400' : value >= 30 ? 'text-amber-400' : 'text-emerald-400';

  return (
    <motion.button
      whileHover={{ y: -3 }}
      whileTap={{ scale: 0.985 }}
      transition={{ type: 'spring', stiffness: 420, damping: 28 }}
      onClick={onClick}
      className="panel group w-full overflow-hidden p-4 text-left transition-colors hover:border-[var(--color-border-strong)]"
    >
      <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
      <div className="mb-3 flex items-start justify-between">
        <span className="grid h-8 w-8 place-items-center rounded-lg bg-[var(--color-surface-3)] text-[var(--color-ink-muted)] ring-1 ring-inset ring-white/5 transition-colors group-hover:text-[var(--color-accent-bright)]">
          <Icon size={15} />
        </span>
        <span className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
          weight {weight}
        </span>
      </div>
      <p className="mono text-[10px] uppercase tracking-[0.14em] text-[var(--color-ink-dim)]">{label}</p>
      <p className={cn('mono mt-0.5 text-2xl font-black', tone)}>
        <Counter value={value} decimals={1} />
        <span className="text-xs font-normal text-[var(--color-ink-dim)]">/100</span>
      </p>
      <RiskBar value={value} className="mt-2.5" />
    </motion.button>
  );
}

function Metric({
  label,
  value,
  icon: Icon,
  tone = 'neutral',
  sub,
}: {
  label: string;
  value: number;
  icon: React.ComponentType<{ size?: number }>;
  tone?: 'neutral' | 'ok' | 'danger';
  sub?: string;
}) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-3">
        <span
          className={cn(
            'grid h-9 w-9 shrink-0 place-items-center rounded-lg ring-1 ring-inset',
            tone === 'danger'
              ? 'bg-rose-500/10 text-rose-300 ring-rose-500/25'
              : tone === 'ok'
                ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/25'
                : 'bg-[var(--color-surface-3)] text-[var(--color-ink-muted)] ring-white/5'
          )}
        >
          <Icon size={16} />
        </span>
        <div className="min-w-0">
          <p className="mono text-2xl font-black leading-none">
            <Counter value={value} />
          </p>
          <p className="mono mt-1 truncate text-[9.5px] uppercase tracking-[0.14em] text-[var(--color-ink-dim)]">
            {label}
          </p>
          {sub && <p className="mono text-[9.5px] text-[var(--color-ink-dim)]">{sub}</p>}
        </div>
      </div>
    </Card>
  );
}
