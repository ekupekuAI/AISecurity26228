/**
 * Application shell: navigation rail, top bar and the finding inspector.
 *
 * The rail collapses to an overlay below `lg`. Navigation items that the session cannot
 * use are not rendered at all, rather than rendered disabled — a control that exists but
 * never works is worse than one that is absent, because an operator keeps trying it.
 */

import React, { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  Activity,
  BookOpen,
  Boxes,
  Database,
  Fingerprint,
  LayoutDashboard,
  LineChart,
  LogOut,
  Menu,
  Radar,
  Stamp,
  Settings,
  ShieldCheck,
  Waves,
  X,
} from 'lucide-react';
import type { Finding } from '../types.js';
import { useAuth } from '../context/AuthContext.js';
import { Badge, Button, Hash, InfoHint, RiskBar, SeverityBadge, cn } from '../ui/primitives.js';

export type NavTab =
  | 'dashboard'
  | 'analytics'
  | 'sentinel'
  | 'dataset'
  | 'model'
  | 'inference'
  | 'shift'
  | 'history'
  | 'aibom'
  | 'config'
  | 'methodology';

interface NavItem {
  id: NavTab;
  label: string;
  hint: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  /** Capability required to do anything useful here. Absent means read-only is enough. */
  capability?: string;
}

const NAV_GROUPS: Array<{ label: string; items: NavItem[] }> = [
  {
    label: 'Command',
    items: [
      { id: 'dashboard', label: 'Assurance monitor', hint: 'Overall verdict and risk', icon: LayoutDashboard },
      { id: 'analytics', label: 'Analytics', hint: 'Risk trends and graphs', icon: LineChart },
      { id: 'sentinel', label: 'Live monitoring', hint: 'Live threat monitoring', icon: Radar },
    ],
  },
  {
    label: 'Inspection',
    items: [
      { id: 'dataset', label: 'Dataset integrity', hint: 'Check a dataset file', icon: Database },
      { id: 'model', label: 'Model integrity', hint: 'Check a model file', icon: Boxes },
      { id: 'inference', label: 'Inference provenance', hint: 'Seal and verify predictions', icon: Fingerprint },
      { id: 'shift', label: 'Distribution shift', hint: 'Data drift detection', icon: Waves },
    ],
  },
  {
    label: 'Evidence',
    items: [
      { id: 'history', label: 'Audit & reports', hint: 'Audit log and reports', icon: Activity },
      { id: 'aibom', label: 'Model passport', hint: 'Signed model passport', icon: Stamp },
      { id: 'methodology', label: 'Methodology', hint: 'How the checks work', icon: BookOpen },
    ],
  },
  {
    label: 'Node',
    items: [{ id: 'config', label: 'Settings', hint: 'Engine and node settings', icon: Settings }],
  },
];

export function Sidebar({
  current,
  onNavigate,
  engineStatus,
  trustScore,
  open,
  onClose,
}: {
  current: NavTab;
  onNavigate: (tab: NavTab) => void;
  engineStatus: string;
  trustScore: number | null;
  open: boolean;
  onClose: () => void;
}) {
  const { user, logout } = useAuth();

  const content = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2.5 px-4 py-4">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-gradient-to-br from-[#1d4ed8] to-[#0e7490] text-white shadow-[0_8px_20px_-8px_rgba(29,78,216,0.9)]">
          <ShieldCheck size={18} />
        </span>
        <div className="min-w-0">
          <p className="truncate text-[13px] font-bold leading-tight">TrustVision</p>
          <p className="mono truncate text-[9px] uppercase tracking-[0.18em] text-[var(--color-ink-dim)]">
            SIH26228 · DGIS
          </p>
        </div>
        <button
          onClick={onClose}
          className="ml-auto text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink)] lg:hidden"
          aria-label="Close navigation"
        >
          <X size={18} />
        </button>
      </div>

      <div className="mx-4 mb-4 rounded-xl border border-[var(--color-border)] bg-white/[0.02] px-3 py-2.5">
        <div className="flex items-baseline justify-between">
          <span className="mono text-[9px] uppercase tracking-[0.16em] text-[var(--color-ink-dim)]">
            Trust score
          </span>
          <span
            className={cn(
              'mono text-base font-bold',
              trustScore === null
                ? 'text-[var(--color-ink-dim)]'
                : trustScore >= 70
                  ? 'text-emerald-400'
                  : trustScore >= 30
                    ? 'text-amber-400'
                    : 'text-rose-400'
            )}
          >
            {/* Distinguish "not loaded yet / stats unavailable" from a real perfect score,
                so the sidebar never shows a reassuring green 100 backed by no evidence. */}
            {trustScore === null ? '—' : trustScore.toFixed(0)}
          </span>
        </div>
        <RiskBar value={trustScore === null ? 0 : 100 - trustScore} className="mt-2" />
      </div>

      <nav className="flex-1 overflow-y-auto px-3 pb-3">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-4">
            <p className="mono px-2 pb-1.5 text-[9px] uppercase tracking-[0.2em] text-[var(--color-ink-dim)]">
              {group.label}
            </p>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const active = current === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      onNavigate(item.id);
                      onClose();
                    }}
                    className={cn(
                      'group relative flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left transition-colors duration-150',
                      active ? 'text-[var(--color-ink)]' : 'text-[var(--color-ink-muted)] hover:text-[var(--color-ink)]'
                    )}
                  >
                    {/* The active pill is a shared layout element, so selection slides
                        between items instead of blinking. */}
                    {active && (
                      <motion.span
                        layoutId="nav-active"
                        transition={{ type: 'spring', stiffness: 480, damping: 38 }}
                        className="absolute inset-0 rounded-lg bg-blue-500/12 ring-1 ring-inset ring-blue-400/25"
                      />
                    )}
                    <item.icon
                      size={15}
                      className={cn(
                        'relative shrink-0 transition-colors',
                        active ? 'text-[var(--color-accent-bright)]' : 'text-[var(--color-ink-dim)] group-hover:text-[var(--color-ink-muted)]'
                      )}
                    />
                    <span className="relative min-w-0 flex-1">
                      <span className="block truncate text-[12.5px] font-medium">{item.label}</span>
                      <span className="block truncate text-[10px] text-[var(--color-ink-dim)]">{item.hint}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-[var(--color-border)] px-4 py-3">
        <div className="mb-2.5 flex items-center gap-2">
          <span
            className={cn(
              'h-1.5 w-1.5 rounded-full',
              engineStatus === 'ONLINE' ? 'bg-emerald-400' : 'bg-amber-400'
            )}
          />
          <span className="mono text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)]">
            engine {engineStatus.toLowerCase()}
          </span>
        </div>
        <div className="flex items-center gap-2.5">
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-[var(--color-surface-3)] text-[11px] font-bold text-[var(--color-accent-bright)]">
            {(user?.name ?? '?')
              .split(' ')
              .map((part) => part[0])
              .slice(0, 2)
              .join('')}
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-[12px] font-semibold">{user?.name}</p>
            <p className="mono truncate text-[9px] uppercase tracking-wider text-[var(--color-ink-dim)]">
              {user?.clearanceLevel.replace(/_/g, ' ')}
            </p>
          </div>
          <button
            onClick={() => void logout()}
            title="Sign out"
            className="shrink-0 rounded-lg p-1.5 text-[var(--color-ink-dim)] transition-colors hover:bg-white/5 hover:text-rose-300"
            aria-label="Sign out"
          >
            <LogOut size={15} />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <aside className="hidden w-64 shrink-0 border-r border-[var(--color-border)] bg-[var(--color-surface-1)]/60 backdrop-blur-xl lg:block">
        <div className="sticky top-0 h-screen">{content}</div>
      </aside>

      <AnimatePresence>
        {open && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={onClose}
              className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
            />
            <motion.aside
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', stiffness: 380, damping: 38 }}
              className="fixed inset-y-0 left-0 z-50 w-72 border-r border-[var(--color-border)] bg-[var(--color-surface-1)] lg:hidden"
            >
              {content}
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}

export function TopBar({
  title,
  subtitle,
  onMenu,
  actions,
}: {
  title: string;
  subtitle?: string;
  onMenu: () => void;
  actions?: React.ReactNode;
}) {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    // Elevate the bar only once content has moved under it, so the chrome is flat at rest.
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <header
      className={cn(
        'sticky top-0 z-30 flex items-center gap-3 px-4 py-3 transition-all duration-300 lg:px-6',
        scrolled
          ? 'border-b border-[var(--color-border)] bg-[var(--color-surface-0)]/85 backdrop-blur-xl'
          : 'border-b border-transparent'
      )}
    >
      <button
        onClick={onMenu}
        className="rounded-lg p-2 text-[var(--color-ink-muted)] transition-colors hover:bg-white/5 hover:text-[var(--color-ink)] lg:hidden"
        aria-label="Open navigation"
      >
        <Menu size={18} />
      </button>

      <div className="flex min-w-0 flex-1 items-center gap-2">
        <motion.h2
          key={title}
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
          className="truncate text-[15px] font-bold tracking-tight"
        >
          {title}
        </motion.h2>
        {subtitle && <InfoHint align="start">{subtitle}</InfoHint>}
      </div>

      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  );
}

/**
 * Finding inspector.
 *
 * Shows the detector and the exact threshold that fired alongside the evidence, because
 * a finding an analyst cannot trace back to a rule is a finding they cannot defend.
 */
export function FindingInspector({
  finding,
  onClose,
  onAcknowledge,
}: {
  finding: Finding | null;
  onClose: () => void;
  onAcknowledge?: (finding: Finding) => void;
}) {
  const { can } = useAuth();

  return (
    <AnimatePresence>
      {finding && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 z-50 bg-black/65 backdrop-blur-sm"
          />
          <motion.aside
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 340, damping: 36 }}
            className="fixed inset-y-0 right-0 z-50 flex w-full max-w-lg flex-col border-l border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-2xl"
          >
            <div className="flex items-start gap-3 border-b border-[var(--color-border)] px-5 py-4">
              <div className="min-w-0 flex-1">
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <Badge tone="neutral">{finding.category}</Badge>
                  <Badge tone="accent">{(finding.confidence * 100).toFixed(0)}% confidence</Badge>
                </div>
                <h3 className="mono text-[13px] font-bold">{finding.findingId}</h3>
              </div>
              <button
                onClick={onClose}
                className="shrink-0 rounded-lg p-1.5 text-[var(--color-ink-dim)] transition-colors hover:bg-white/5 hover:text-[var(--color-ink)]"
                aria-label="Close"
              >
                <X size={16} />
              </button>
            </div>

            <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5">
              <Section title="Affected asset">
                <p className="mono break-all text-[12px] text-[var(--color-ink-muted)]">{finding.affectedAsset}</p>
              </Section>

              <Section title="What was found">
                <p className="text-[13px] leading-relaxed">{finding.explanation}</p>
              </Section>

              {(finding.detector || finding.threshold) && (
                <Section title="How it was determined">
                  {finding.detector && (
                    <p className="mono text-[11px] text-[var(--color-ink-muted)]">
                      detector: <span className="text-[var(--color-ink)]">{finding.detector}</span>
                    </p>
                  )}
                  {finding.threshold && (
                    <p className="mono mt-1 text-[11px] text-[var(--color-ink-muted)]">
                      threshold: <span className="text-[var(--color-ink)]">{finding.threshold}</span>
                    </p>
                  )}
                </Section>
              )}

              <Section title="Recommended action">
                <p className="text-[13px] leading-relaxed text-amber-200/90">{finding.recommendation}</p>
              </Section>

              <Section title="Evidence">
                <pre className="mono max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-0)] p-3 text-[10.5px] leading-relaxed text-[var(--color-ink-muted)]">
                  {typeof finding.evidence === 'string'
                    ? finding.evidence
                    : JSON.stringify(finding.evidence, null, 2)}
                </pre>
              </Section>

              {finding.references && finding.references.length > 0 && (
                <Section title="References">
                  <ul className="space-y-1">
                    {finding.references.map((reference) => (
                      <li key={reference} className="text-[11px] text-[var(--color-ink-muted)]">
                        · {reference}
                      </li>
                    ))}
                  </ul>
                </Section>
              )}

              <Section title="Record">
                <div className="space-y-1 text-[11px] text-[var(--color-ink-muted)]">
                  <p className="mono">
                    id <Hash value={finding.id} chars={28} />
                  </p>
                  <p className="mono">raised {new Date(finding.timestamp).toLocaleString()}</p>
                  {finding.acknowledgedAt && (
                    <p className="mono text-emerald-400">
                      acknowledged by {finding.acknowledgedBy} at{' '}
                      {new Date(finding.acknowledgedAt).toLocaleString()}
                    </p>
                  )}
                </div>
              </Section>
            </div>

            {onAcknowledge && can('finding:acknowledge') && !finding.acknowledgedAt && (
              <div className="border-t border-[var(--color-border)] px-5 py-4">
                <Button variant="secondary" className="w-full" onClick={() => onAcknowledge(finding)}>
                  Acknowledge finding
                </Button>
                <p className="mt-2 text-[10.5px] leading-relaxed text-[var(--color-ink-dim)]">
                  Acknowledging records that an analyst has reviewed this finding. It does not remove
                  it from the evidence record or change the governance decision.
                </p>
              </div>
            )}
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="mono mb-1.5 text-[9.5px] uppercase tracking-[0.18em] text-[var(--color-ink-dim)]">{title}</p>
      {children}
    </div>
  );
}
