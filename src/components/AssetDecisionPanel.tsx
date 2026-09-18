/**
 * Per-asset governance surface for the Model and Dataset result views.
 *
 * Two jobs. First, the {@link DegradedBanner}: when the Python assurance engine was
 * unreachable and the gateway ran the reduced fallback, that must be impossible to miss --
 * a full-width banner, not a small chip -- because a degraded result that reads like a
 * completed one is exactly how an un-inspected asset gets waved through.
 *
 * Second, the {@link AssetDecisionPanel}: the ACCEPT / REVIEW / QUARANTINE verdict for THIS
 * asset, computed from this asset's own evidence. The dashboard shows the node-wide posture;
 * this shows the decision an operator actually acts on for the checkpoint or corpus in front
 * of them.
 */

import { AlertTriangle, PlugZap, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { GovernanceEvaluation } from '../types.js';
import { Card, RiskBar, cn } from '../ui/primitives.js';

const DECISION_STYLE = {
  ACCEPT: {
    ring: 'ring-emerald-500/30',
    glow: 'from-emerald-500/12',
    text: 'text-emerald-300',
    icon: ShieldCheck,
    lead: 'Authorised for operational deployment',
  },
  REVIEW: {
    ring: 'ring-amber-500/30',
    glow: 'from-amber-500/12',
    text: 'text-amber-300',
    icon: AlertTriangle,
    lead: 'Human-in-the-loop triage required',
  },
  QUARANTINE: {
    ring: 'ring-rose-500/30',
    glow: 'from-rose-500/12',
    text: 'text-rose-300',
    icon: ShieldAlert,
    lead: 'Immediate operational quarantine',
  },
} as const;

export function DegradedBanner({ reason }: { reason?: string }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3">
      <PlugZap size={18} className="mt-0.5 shrink-0 text-amber-300" />
      <div className="min-w-0">
        <p className="text-[13px] font-semibold text-amber-200">
          Degraded assessment — the assurance engine was unreachable
        </p>
        <p className="mt-0.5 text-[11.5px] leading-relaxed text-amber-100/80">
          Only hashing, container structure and a reduced opcode scan ran — the deep detectors did not. A coverage gap,
          not a clean result, so the asset cannot be certified and the decision is capped at REVIEW.
          {reason ? ` Reason: ${reason}.` : ''}
        </p>
      </div>
    </div>
  );
}

export function AssetDecisionPanel({ decision }: { decision: GovernanceEvaluation }) {
  const style = DECISION_STYLE[decision.decision] ?? DECISION_STYLE.REVIEW;
  const Icon = style.icon;

  return (
    <Card className={cn('relative overflow-hidden ring-1', style.ring)}>
      <div className={cn('absolute inset-0 bg-gradient-to-br to-transparent', style.glow)} aria-hidden />
      <div className="relative grid gap-6 p-5 lg:grid-cols-[auto_1fr]">
        <div className="flex items-center gap-4">
          <span
            className={cn(
              'grid h-14 w-14 shrink-0 place-items-center rounded-2xl bg-[var(--color-surface-0)]/60 ring-1 ring-inset',
              style.ring,
              style.text
            )}
          >
            <Icon size={26} />
          </span>
          <div>
            <p className="mono text-[9.5px] uppercase tracking-[0.2em] text-[var(--color-ink-dim)]">Asset decision</p>
            <p className={cn('mono text-3xl font-black tracking-tight', style.text)}>{decision.decision}</p>
            <p className="mt-0.5 text-[11.5px] text-[var(--color-ink-muted)]">{style.lead}</p>
          </div>
        </div>

        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-baseline gap-x-6 gap-y-1">
            <span className="mono text-[11px] text-[var(--color-ink-muted)]">
              asset risk <span className="text-lg font-bold text-[var(--color-ink)]">{decision.overallRisk.toFixed(1)}</span>/100
            </span>
            <span className="mono text-[11px] text-[var(--color-ink-muted)]">
              trust <span className="text-lg font-bold text-[var(--color-ink)]">{decision.trustScore.toFixed(1)}</span>/100
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
          <p className="mt-2 text-[11.5px] leading-relaxed text-[var(--color-ink)]">
            <span className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">Action</span>{' '}
            {decision.actionRequired}
          </p>
        </div>
      </div>
    </Card>
  );
}
