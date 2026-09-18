/**
 * Pieces shared between the inspection pages.
 */

import React, { useCallback, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { CheckCircle2, FileWarning, Lock, ShieldQuestion, Stamp, Upload, XCircle } from 'lucide-react';
import type { CoverageEntry, Finding } from '../../types.js';
import { Badge, Button, Card, CardHeader, EmptyState, SeverityBadge, Spinner, cn } from '../../ui/primitives.js';
import { useAuth } from '../../context/AuthContext.js';
import { downloadAibom, generateAibom } from '../../api/client.js';

/**
 * Drag-and-drop upload surface.
 *
 * Shows its own disabled reason rather than silently doing nothing: a control that is
 * greyed out with no explanation is the most common way an operator gets stuck.
 */
export function UploadZone({
  title,
  hint,
  icon,
  accept,
  busy,
  disabled,
  deniedMessage,
  onFile,
}: {
  title: string;
  hint: string;
  icon: React.ReactNode;
  accept: string;
  busy: boolean;
  disabled?: boolean;
  deniedMessage?: string;
  onFile: (file: File) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [selected, setSelected] = useState<File | null>(null);

  const accepted = accept.split(',').map((value) => value.trim().toLowerCase());

  const hasAllowedExtension = useCallback(
    (name: string) => {
      const dot = name.lastIndexOf('.');
      if (dot < 0) return false;
      return accepted.includes(name.slice(dot).toLowerCase());
    },
    [accepted]
  );

  const choose = useCallback(
    (file: File | undefined) => {
      if (!file) return;
      setSelected(file);
      onFile(file);
    },
    [onFile]
  );

  return (
    <Card className={cn('relative overflow-hidden transition-colors', dragging && 'border-blue-500/60')}>
      <div
        onDragOver={(event) => {
          if (disabled || busy) return;
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          if (disabled || busy) return;
          choose(event.dataTransfer.files?.[0]);
        }}
        className="relative p-6"
      >
        <AnimatePresence>
          {dragging && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="pointer-events-none absolute inset-0 bg-blue-500/8"
            />
          )}
        </AnimatePresence>

        <div className="relative flex flex-col items-center gap-4 text-center">
          <motion.span
            animate={busy ? { scale: [1, 1.06, 1] } : { scale: 1 }}
            transition={busy ? { duration: 1.6, repeat: Infinity, ease: 'easeInOut' } : undefined}
            className={cn(
              'grid h-14 w-14 place-items-center rounded-2xl ring-1 ring-inset transition-colors',
              busy
                ? 'bg-blue-500/12 text-blue-300 ring-blue-500/30'
                : 'bg-[var(--color-surface-3)] text-[var(--color-ink-muted)] ring-white/5'
            )}
          >
            {busy ? <Spinner className="h-5 w-5" /> : icon}
          </motion.span>

          <div className="max-w-xl">
            <h3 className="text-[15px] font-bold">{busy ? 'Inspection in progress' : title}</h3>
            <p className="mt-1.5 text-[12px] leading-relaxed text-[var(--color-ink-muted)]">
              {busy
                ? 'The assurance engine is running its detector battery. A model with trigger inversion can take up to a minute.'
                : hint}
            </p>
          </div>

          {disabled ? (
            <Badge tone="warn">{deniedMessage ?? 'Not permitted for this role'}</Badge>
          ) : (
            <>
              <input
                ref={inputRef}
                type="file"
                accept={accept}
                className="hidden"
                onChange={(event) => choose(event.target.files?.[0])}
              />
              <Button
                variant="primary"
                onClick={() => inputRef.current?.click()}
                disabled={busy}
                icon={<Upload size={16} />}
              >
                Choose file
              </Button>
              <p className="mono text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                or drop it here · {accepted.join(' ')}
              </p>
            </>
          )}

          {selected && !busy && (
            <p className="mono text-[10.5px] text-[var(--color-ink-dim)]">
              last submitted: {selected.name} ({(selected.size / 1024 / 1024).toFixed(1)} MB)
              {!hasAllowedExtension(selected.name) && (
                <span className="ml-2 text-amber-400">unexpected extension</span>
              )}
            </p>
          )}
        </div>

        {busy && (
          <div className="absolute inset-x-0 bottom-0 h-0.5 overflow-hidden">
            <motion.div
              animate={{ x: ['-100%', '100%'] }}
              transition={{ duration: 1.4, repeat: Infinity, ease: 'linear' }}
              className="h-full w-1/3 bg-gradient-to-r from-transparent via-blue-400 to-transparent"
            />
          </div>
        )}
      </div>
    </Card>
  );
}

export function FindingList({
  findings,
  onSelect,
  title = 'Findings',
}: {
  findings: Finding[];
  onSelect: (finding: Finding) => void;
  title?: string;
}) {
  const critical = findings.filter((finding) => finding.severity === 'CRITICAL').length;

  return (
    <Card>
      <CardHeader
        title={title}
        subtitle="Every finding carries the detector that produced it and the threshold that fired."
        icon={<FileWarning size={15} />}
        action={
          findings.length > 0 ? (
            <Badge tone={critical > 0 ? 'danger' : 'neutral'}>
              {critical > 0 ? `${critical} critical / ${findings.length}` : findings.length}
            </Badge>
          ) : undefined
        }
      />
      <div className="px-2 pb-2">
        {findings.length === 0 ? (
          <EmptyState
            icon={<CheckCircle2 size={20} />}
            title="No findings raised"
            description="Every detector that ran completed without flagging this asset. Check the coverage matrix for what was not tested."
          />
        ) : (
          <ul className="space-y-1">
            {findings.map((finding) => (
              <li key={finding.id}>
                <motion.button
                  whileHover={{ x: 3 }}
                  whileTap={{ scale: 0.995 }}
                  transition={{ type: 'spring', stiffness: 500, damping: 34 }}
                  onClick={() => onSelect(finding)}
                  className="flex w-full items-start gap-3 rounded-xl px-3 py-2.5 text-left transition-colors hover:bg-white/[0.035]"
                >
                  <span className="mt-0.5 shrink-0">
                    <SeverityBadge severity={finding.severity} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-baseline gap-2">
                      <span className="mono truncate text-[11.5px] font-semibold">{finding.findingId}</span>
                      {finding.affectedAsset && (
                        <span className="mono truncate text-[10px] text-[var(--color-ink-dim)]">
                          {finding.affectedAsset}
                        </span>
                      )}
                    </span>
                    <span className="mt-0.5 block line-clamp-2 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                      {finding.explanation}
                    </span>
                    {finding.threshold && (
                      <span className="mono mt-1 block truncate text-[10px] text-[var(--color-ink-dim)]">
                        {finding.threshold}
                      </span>
                    )}
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
  );
}

/**
 * Attack-coverage matrix.
 *
 * The uncovered rows are the point. A matrix showing only successes would be marketing;
 * this is the document that tells an assessor what the verdict does not cover.
 */
export function CoverageMatrix({ entries }: { entries: CoverageEntry[] }) {
  const covered = entries.filter((entry) => entry.covered).length;

  return (
    <Card>
      <CardHeader
        title="Attack coverage & limitations"
        subtitle="What this assessment tested, how confidently, and what it explicitly did not test."
        icon={<ShieldQuestion size={15} />}
        action={
          <Badge tone="neutral">
            {covered}/{entries.length} covered
          </Badge>
        }
      />
      <div className="space-y-px bg-[var(--color-border)] px-px pb-px">
        {entries.map((entry) => (
          <div key={`${entry.threat}-${entry.technique}`} className="bg-[var(--color-surface-1)] px-5 py-3.5">
            <div className="flex items-start gap-3">
              <span className="mt-0.5 shrink-0">
                {entry.covered ? (
                  <CheckCircle2 size={15} className="text-emerald-400" />
                ) : (
                  <XCircle size={15} className="text-[var(--color-ink-dim)]" />
                )}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
                  <p className={cn('text-[12.5px] font-semibold', !entry.covered && 'text-[var(--color-ink-muted)]')}>
                    {entry.threat}
                  </p>
                  <p className="mono text-[10px] text-[var(--color-ink-dim)]">{entry.technique}</p>
                  {entry.covered && (
                    <span
                      className={cn(
                        'mono text-[10px]',
                        entry.confidence >= 0.8
                          ? 'text-emerald-400'
                          : entry.confidence >= 0.5
                            ? 'text-amber-400'
                            : 'text-orange-400'
                      )}
                    >
                      {(entry.confidence * 100).toFixed(0)}% confidence
                    </span>
                  )}
                </div>
                <p className="mt-1 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">{entry.method}</p>
                <p
                  className={cn(
                    'mt-1 text-[11px] leading-relaxed',
                    entry.covered ? 'text-[var(--color-ink-dim)]' : 'text-amber-200/70'
                  )}
                >
                  <span className="mono uppercase tracking-wider">limitation · </span>
                  {entry.limitation}
                </p>
                {entry.references.length > 0 && (
                  <p className="mono mt-1 text-[10px] text-[var(--color-ink-dim)]">
                    {entry.references.join(' · ')}
                  </p>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

/** Small labelled figure used across the inspection panels. */
export function Stat({ label, value, tone }: { label: string; value: React.ReactNode; tone?: string }) {
  return (
    <div>
      <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">{label}</p>
      <p className={cn('mono truncate text-[12px] font-semibold', tone)}>{value}</p>
    </div>
  );
}

/**
 * Issue a signed AI-BOM passport for the asset on this result page.
 *
 * Closes the analyse -> certify loop: the operator no longer has to leave for the passport
 * page and re-pick the analysis. Capability-gated, so it never appears for a read-only role.
 * On success the passport is downloaded immediately -- the portable artefact is the point.
 */
export function IssuePassport({
  analysisId,
  pushToast,
}: {
  analysisId: string;
  pushToast: (tone: 'ok' | 'error' | 'info', title: string, detail?: string) => void;
}) {
  const { can } = useAuth();
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState(false);

  if (!can('report:generate')) return null;

  const issue = async () => {
    setBusy(true);
    try {
      const passport = await generateAibom(analysisId);
      await downloadAibom(passport.bomId);
      setIssued(true);
      pushToast('ok', 'Passport issued', `${passport.bomId} · signed and downloaded`);
    } catch (error) {
      pushToast('error', 'Could not issue passport', error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Button variant="secondary" size="sm" onClick={issue} loading={busy} icon={busy ? undefined : <Stamp size={14} />}>
      {issued ? 'Re-issue passport' : 'Issue signed passport'}
    </Button>
  );
}

export function LockNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-[var(--color-border)] bg-white/[0.02] px-3 py-2.5">
      <Lock size={12} className="mt-0.5 shrink-0 text-[var(--color-ink-dim)]" />
      <p className="text-[11px] leading-relaxed text-[var(--color-ink-dim)]">{children}</p>
    </div>
  );
}
