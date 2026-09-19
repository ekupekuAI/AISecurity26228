/**
 * Node configuration and deployment posture.
 *
 * Everything on this page is read from the running node, not from a constant. If the
 * signing key is missing, this page says so and the badge goes amber — a console that
 * always draws a green "signed" chip is worse than no chip at all, because it trains the
 * operator to stop reading it.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Database,
  Eraser,
  FlaskConical,
  KeyRound,
  Lock,
  Network,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Unplug,
  XCircle,
} from 'lucide-react';
import type { SystemStatus } from '../../types.js';
import {
  clearEvaluationData,
  fetchSystemStatus,
  seedEvaluationData,
  updateEngineUrl,
} from '../../api/client.js';
import { useAuth } from '../../context/AuthContext.js';
import { Badge, Button, Card, CardHeader, Skeleton, cn } from '../../ui/primitives.js';
import { LockNote, Stat } from './parts.js';
import type { PageProps } from './shared.js';

export const ConfigPage: React.FC<PageProps> = ({ onRefresh, pushToast }) => {
  const { can, user, changePassword } = useAuth();

  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [engineUrl, setEngineUrl] = useState('');
  const [savingEngine, setSavingEngine] = useState(false);
  const [seeding, setSeeding] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [seedResult, setSeedResult] = useState<Awaited<ReturnType<typeof seedEvaluationData>> | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await fetchSystemStatus();
      setStatus(result);
      setEngineUrl(result.engine.url);
    } catch (error) {
      pushToast('error', 'Could not read node status', error instanceof Error ? error.message : undefined);
    } finally {
      setLoading(false);
    }
  }, [pushToast]);

  useEffect(() => {
    void load();
  }, [load]);

  const saveEngine = async () => {
    setSavingEngine(true);
    try {
      const result = await updateEngineUrl(engineUrl.trim());
      pushToast(
        'ok',
        result.changed ? 'Engine endpoint updated' : 'Endpoint unchanged',
        result.mlServiceUrl
      );
      await load();
      void onRefresh();
    } catch (error) {
      // The refusal path matters more than the success path: pointing the engine at an
      // external host is what exfiltration looks like from here, and the server logs it.
      pushToast('error', 'Endpoint refused', error instanceof Error ? error.message : undefined);
    } finally {
      setSavingEngine(false);
    }
  };

  const seed = async () => {
    setSeeding(true);
    try {
      const result = await seedEvaluationData();
      setSeedResult(result);
      pushToast('ok', 'Evaluation fixture loaded', result.message);
      await load();
      void onRefresh();
    } catch (error) {
      pushToast('error', 'Seeding failed', error instanceof Error ? error.message : undefined);
    } finally {
      setSeeding(false);
    }
  };

  const clear = async () => {
    // This removes real analyses, not just the demo fixture, and cannot be undone. The
    // audit ledger is retained, but the evidence rows are gone -- so it is an explicit,
    // confirmed action rather than a single click.
    const confirmed = window.confirm(
      'Remove ALL evaluation records?\n\n' +
        'This deletes every analysis, finding, inference record, asset and issued AI-BOM on ' +
        'this node -- real records as well as any demo fixture. It cannot be undone.\n\n' +
        'The append-only audit ledger is kept, and the purge is recorded in it.'
    );
    if (!confirmed) return;
    setClearing(true);
    try {
      const result = await clearEvaluationData();
      setSeedResult(null);
      pushToast('ok', 'All evaluation records removed', result.note);
      await load();
      void onRefresh();
    } catch (error) {
      pushToast('error', 'Clear failed', error instanceof Error ? error.message : undefined);
    } finally {
      setClearing(false);
    }
  };

  if (loading && !status) {
    return (
      <div className="grid gap-5 lg:grid-cols-2">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-56 w-full rounded-2xl" />
        ))}
      </div>
    );
  }

  if (!status) {
    return (
      <Card>
        <p className="flex items-center gap-2 p-5 text-[12px] text-amber-200">
          <AlertTriangle size={15} /> Node status is unavailable. The gateway may be restarting.
        </p>
      </Card>
    );
  }

  const engineOnline = status.engine.status === 'ONLINE';

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-2">
        {/* ----------------------------------------------------- engine */}
        <Card className={cn('ring-1', engineOnline ? 'ring-emerald-500/20' : 'ring-amber-500/25')}>
          <CardHeader
            title="Assurance engine"
            subtitle="The Python service that performs every real detector. Without it the gateway falls back to a deliberately limited scanner."
            icon={<Cpu size={15} />}
            action={
              <Badge tone={engineOnline ? 'ok' : 'warn'} pulse={!engineOnline}>
                {status.engine.status}
              </Badge>
            }
          />
          <div className="space-y-3.5 px-5 pb-5">
            <label className="block">
              <span className="mono mb-1 block text-[9.5px] uppercase tracking-[0.14em] text-[var(--color-ink-dim)]">
                endpoint
              </span>
              <div className="flex gap-2">
                <input
                  value={engineUrl}
                  onChange={(event) => setEngineUrl(event.target.value)}
                  disabled={!can('system:configure')}
                  className="mono w-full rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface-0)]/70 px-3 py-2 text-[11.5px] outline-none transition-colors focus:border-blue-500/60 focus:shadow-[0_0_0_3px_rgba(59,130,246,0.1)] disabled:opacity-50"
                />
                <Button
                  onClick={saveEngine}
                  loading={savingEngine}
                  disabled={!can('system:configure') || engineUrl.trim() === status.engine.url}
                >
                  Apply
                </Button>
              </div>
            </label>

            {status.engine.error && (
              <p className="mono rounded-lg bg-amber-500/8 px-3 py-2 text-[10.5px] leading-relaxed text-amber-200">
                {status.engine.error}
              </p>
            )}

            <LockNote>
              Only loopback and RFC 1918 addresses are accepted. A request to point this at a public
              host is refused and written to the audit ledger as{' '}
              <code className="mono">ENGINE_URL_CHANGE_REFUSED</code>, because on an air-gapped node
              that request is indistinguishable from an attempt to exfiltrate submitted assets.
            </LockNote>

            {status.engine.capabilities && (
              <div>
                <p className="mono mb-1.5 text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                  engine capabilities
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(status.engine.capabilities).map(([name, available]) => (
                    <span
                      key={name}
                      className={cn(
                        'mono inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[10px] ring-1 ring-inset',
                        available
                          ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/25'
                          : 'bg-white/4 text-[var(--color-ink-dim)] ring-white/10'
                      )}
                    >
                      {available ? <CheckCircle2 size={10} /> : <XCircle size={10} />}
                      {name}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {status.engine.backbone && (
              <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/50 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="mono text-[11px] font-semibold">{status.engine.backbone.architecture}</span>
                  <Badge
                    tone={
                      status.engine.backbone.source === 'RANDOM_INIT_FALLBACK'
                        ? 'warn'
                        : status.engine.backbone.source === 'UNAVAILABLE'
                          ? 'danger'
                          : 'ok'
                    }
                  >
                    {status.engine.backbone.source.replace(/_/g, ' ').toLowerCase()}
                  </Badge>
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-[var(--color-ink-muted)]">
                  {status.engine.backbone.limitation}
                </p>
                <div className="mt-2 grid grid-cols-2 gap-2">
                  <Stat label="embedding dim" value={status.engine.backbone.embeddingDim} />
                  <Stat
                    label="confidence multiplier"
                    value={status.engine.backbone.confidenceMultiplier.toFixed(2)}
                    tone={status.engine.backbone.confidenceMultiplier < 1 ? 'text-amber-400' : undefined}
                  />
                </div>
                {status.engine.backbone.weightsSha256 && (
                  <p className="mono mt-2 break-all text-[9.5px] text-[var(--color-ink-dim)]">
                    weights sha-256 · {status.engine.backbone.weightsSha256}
                  </p>
                )}
              </div>
            )}
          </div>
        </Card>

        {/* ---------------------------------------------------- signing */}
        <Card className={cn('ring-1', status.signing.available ? 'ring-emerald-500/20' : 'ring-amber-500/25')}>
          <CardHeader
            title="Signing keyring"
            subtitle="One Ed25519 key, shared between the Node gateway and the Python engine so a record sealed by either verifies against the other."
            icon={<KeyRound size={15} />}
            action={
              <Badge tone={status.signing.available ? 'ok' : 'warn'}>
                {status.signing.available ? 'key loaded' : 'unsigned mode'}
              </Badge>
            }
          />
          <div className="space-y-3 px-5 pb-5">
            {status.signing.publicKey ? (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <Stat label="key id" value={status.signing.publicKey.keyId} />
                  <Stat label="algorithm" value={status.signing.publicKey.algorithm} />
                </div>
                <div>
                  <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                    fingerprint
                  </p>
                  <p className="mono break-all text-[11px] text-emerald-300">
                    {status.signing.publicKey.fingerprint}
                  </p>
                </div>
                <div>
                  <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                    public key (base64)
                  </p>
                  <p className="mono break-all text-[10.5px] text-blue-300">
                    {status.signing.publicKey.publicKey}
                  </p>
                </div>
                <p className="mono text-[10px] text-[var(--color-ink-dim)]">
                  created {new Date(status.signing.publicKey.createdAt).toLocaleString()}
                </p>
              </>
            ) : (
              <p className="flex items-start gap-2 rounded-lg bg-amber-500/8 px-3 py-2.5 text-[11.5px] leading-relaxed text-amber-200">
                <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                {status.signing.error ??
                  'No signing key is loaded. Records are still hashed and chained, but a party who can write to the database could recompute a digest. Only a signature makes that detectable.'}
              </p>
            )}

            <LockNote>
              The private key lives in a 0600 keyring file outside the web root and is never sent to
              the browser. This panel shows the public half only — that is all a verifier needs.
            </LockNote>
          </div>
        </Card>

        {/* ------------------------------------------------------ posture */}
        <Card>
          <CardHeader
            title="Deployment posture"
            subtitle="What this specific process is configured to do right now."
            icon={<Server size={15} />}
            action={
              <button
                onClick={load}
                className="mono flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink)]"
              >
                <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> refresh
              </button>
            }
          />
          <div className="space-y-3 px-5 pb-5">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <Stat label="service" value={status.service} />
              <Stat label="version" value={status.version} />
              <Stat
                label="environment"
                value={status.environment}
                tone={status.environment === 'production' ? 'text-emerald-400' : 'text-amber-400'}
              />
              <Stat
                label="air-gapped"
                value={status.airGapped ? 'yes' : 'no'}
                tone={status.airGapped ? 'text-emerald-400' : 'text-amber-400'}
              />
              <Stat
                label="evaluation mode"
                value={status.demoMode ? 'enabled' : 'disabled'}
                tone={status.demoMode ? 'text-amber-400' : 'text-emerald-400'}
              />
              <Stat
                label="audit ledger"
                value={status.auditLedger.valid ? 'valid' : 'broken'}
                tone={status.auditLedger.valid ? 'text-emerald-400' : 'text-rose-400'}
              />
            </div>

            <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/50 p-3">
              <p className="mono mb-2 flex items-center gap-1.5 text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                <Database size={11} /> database
              </p>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {Object.entries(status.database).map(([key, value]) => (
                  <Stat key={key} label={key.replace(/_/g, ' ')} value={String(value)} />
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/50 p-3">
              <p className="mono mb-2 text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                risk weights and decision bands
              </p>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {Object.entries(status.riskWeights).map(([key, value]) => (
                  <Stat key={key} label={key.replace(/Weight$/, '')} value={Number(value).toFixed(2)} />
                ))}
              </div>
              <p className="mono mt-2 text-[10.5px] text-[var(--color-ink-dim)]">
                accept below {status.decisionThresholds.acceptBelow} · quarantine at or above{' '}
                {status.decisionThresholds.quarantineAtOrAbove} · override rules can force QUARANTINE
                regardless of the arithmetic
              </p>
            </div>

            {!status.airGapped && (
              <p className="flex items-start gap-2 rounded-lg bg-amber-500/8 px-3 py-2.5 text-[11px] leading-relaxed text-amber-200">
                <Unplug size={13} className="mt-0.5 shrink-0" />
                This node reports outbound network access. On the target deployment the engine must
                be reachable only over loopback, with no route to the internet.
              </p>
            )}
          </div>
        </Card>

        {/* ---------------------------------------------------- identity */}
        <Card>
          <CardHeader
            title="Session and credentials"
            subtitle="Your role decides what this console will let you do; the server enforces it independently."
            icon={<Lock size={15} />}
          />
          <div className="space-y-3.5 px-5 pb-5">
            <div className="grid grid-cols-2 gap-3">
              <Stat label="operator" value={user?.name ?? '—'} />
              <Stat label="badge" value={user?.badgeId ?? '—'} />
              <Stat label="role" value={(user?.role ?? '').replace(/_/g, ' ').toLowerCase()} />
              <Stat label="clearance" value={(user?.clearanceLevel ?? '').replace(/_/g, ' ').toLowerCase()} />
            </div>

            <div>
              <p className="mono mb-1.5 text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                granted capabilities
              </p>
              <div className="flex flex-wrap gap-1.5">
                {(user?.capabilities ?? []).map((capability) => (
                  <Badge key={capability} tone="accent">
                    {capability}
                  </Badge>
                ))}
              </div>
            </div>

            <PasswordPanel
              onSubmit={changePassword}
              onDone={(message) => pushToast('ok', 'Password changed', message)}
              onError={(message) => pushToast('error', 'Password change failed', message)}
              mustChange={Boolean(user?.mustChangePassword)}
            />
          </div>
        </Card>
      </div>

      {/* ------------------------------------------------- evaluation data */}
      {status.demoMode && can('demo:manage') && (
        <Card className="ring-1 ring-amber-500/20">
          <CardHeader
            title="Evaluation fixture"
            subtitle="Runs a genuine seal, a genuine field alteration and a genuine re-verification, then stores whatever the verifier actually concluded."
            icon={<FlaskConical size={15} />}
            action={<Badge tone="warn">evaluation mode only</Badge>}
          />
          <div className="space-y-3.5 px-5 pb-5">
            <div className="flex flex-wrap gap-2">
              <Button onClick={seed} loading={seeding} icon={<FlaskConical size={14} />}>
                Load evaluation fixture
              </Button>
              <Button variant="danger" onClick={clear} loading={clearing} icon={<Eraser size={14} />}>
                Remove all evaluation records
              </Button>
            </div>

            <p className="text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
              <strong>Remove all evaluation records</strong> gives you a clean node to test against:
              it deletes every stored analysis, finding, inference record, asset and issued AI-BOM —
              real records as well as the demo fixture — so the dashboard returns to an empty state
              until you run new analyses. The append-only audit ledger is retained.
            </p>

            <AnimatePresence>
              {seedResult && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="overflow-hidden"
                >
                  <div className="space-y-2 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/60 p-3.5">
                    <p className="mono text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                      tamper demonstration
                    </p>
                    <div className="grid gap-2 sm:grid-cols-2">
                      <Stat label="sealed prediction" value={seedResult.tamperDemonstration.sealedPrediction} />
                      <Stat
                        label="presented prediction"
                        value={seedResult.tamperDemonstration.presentedPrediction}
                        tone="text-rose-400"
                      />
                    </div>
                    <div>
                      <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                        sealed digest
                      </p>
                      <p className="mono break-all text-[10px] text-[var(--color-ink-muted)]">
                        {seedResult.tamperDemonstration.sealedDigest}
                      </p>
                    </div>
                    <div>
                      <p className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                        recomputed digest
                      </p>
                      <p className="mono break-all text-[10px] text-rose-300">
                        {seedResult.tamperDemonstration.recomputedDigest}
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone={seedResult.tamperDemonstration.verificationStatus === 'VERIFIED' ? 'ok' : 'danger'}>
                        {seedResult.tamperDemonstration.verificationStatus}
                      </Badge>
                      {seedResult.tamperDemonstration.alteredFields.map((field) => (
                        <Badge key={field} tone="danger">
                          {field}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <LockNote>
              Every record created here is flagged and shown with an <strong>eval</strong> chip
              throughout the console, and this panel disappears entirely when the node starts with
              evaluation mode off — which it refuses to leave enabled in a production build.
            </LockNote>
          </div>
        </Card>
      )}

      {!status.demoMode && (
        <Card>
          <p className="flex items-center gap-2 px-5 py-4 text-[11.5px] text-[var(--color-ink-muted)]">
            <ShieldCheck size={14} className="text-emerald-400" />
            Evaluation mode is off: this node holds operational records only, and the fixture loader
            is not reachable.
          </p>
        </Card>
      )}

      <Card>
        <CardHeader
          title="Network posture"
          subtitle="What this console talks to, and what it refuses to."
          icon={<Network size={15} />}
        />
        <ul className="space-y-2 px-5 pb-5 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
          {[
            'The browser talks only to this gateway, same-origin, with an httpOnly __Host- session cookie and a double-submit CSRF token held in memory.',
            'The gateway talks only to the assurance engine on a loopback or private address. Any other destination is refused before a socket is opened.',
            'No analytics, font CDN, telemetry or error-reporting service is contacted. The content-security policy sets default-src to self and frame-ancestors to none.',
            'Submitted datasets and models are held in memory for the duration of the call and are never written to disk under a caller-supplied name.',
          ].map((line) => (
            <li key={line} className="flex gap-2">
              <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-emerald-400" />
              {line}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
};

/**
 * Password change.
 *
 * The server invalidates every session on success, so the console returns to the sign-in
 * screen. That is deliberate and is stated here rather than appearing as a mysterious
 * logout.
 */
function PasswordPanel({
  onSubmit,
  onDone,
  onError,
  mustChange,
}: {
  onSubmit: (current: string, next: string) => Promise<string>;
  onDone: (message: string) => void;
  onError: (message: string) => void;
  mustChange: boolean;
}) {
  const [open, setOpen] = useState(mustChange);
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);

  const mismatch = confirm.length > 0 && next !== confirm;
  const tooShort = next.length > 0 && next.length < 12;

  const submit = async () => {
    setBusy(true);
    try {
      const message = await onSubmit(current, next);
      onDone(message);
      setCurrent('');
      setNext('');
      setConfirm('');
      setOpen(false);
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Rejected.');
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <Button size="sm" onClick={() => setOpen(true)} icon={<KeyRound size={13} />}>
        Change password
      </Button>
    );
  }

  return (
    <div className="space-y-2.5 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/50 p-3.5">
      {mustChange && (
        <p className="flex items-start gap-2 text-[11px] leading-relaxed text-amber-200">
          <AlertTriangle size={13} className="mt-0.5 shrink-0" />
          This account still holds its bootstrap password. Change it before the node is used for
          anything real.
        </p>
      )}
      {(['current', 'new', 'confirm'] as const).map((field) => (
        <input
          key={field}
          type="password"
          autoComplete={field === 'current' ? 'current-password' : 'new-password'}
          placeholder={
            field === 'current' ? 'Current password' : field === 'new' ? 'New password (min 12)' : 'Confirm new password'
          }
          value={field === 'current' ? current : field === 'new' ? next : confirm}
          onChange={(event) =>
            field === 'current'
              ? setCurrent(event.target.value)
              : field === 'new'
                ? setNext(event.target.value)
                : setConfirm(event.target.value)
          }
          className="w-full rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface-0)]/70 px-3 py-2 text-[12px] outline-none transition-colors focus:border-blue-500/60 focus:shadow-[0_0_0_3px_rgba(59,130,246,0.1)]"
        />
      ))}
      {tooShort && <p className="mono text-[10px] text-amber-400">at least 12 characters</p>}
      {mismatch && <p className="mono text-[10px] text-rose-400">the two entries differ</p>}
      <div className="flex gap-2">
        <Button
          variant="primary"
          size="sm"
          onClick={submit}
          loading={busy}
          disabled={!current || next.length < 12 || next !== confirm}
        >
          Update password
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
          Cancel
        </Button>
      </div>
      <p className="text-[10.5px] leading-relaxed text-[var(--color-ink-dim)]">
        Every active session is destroyed on success, including this one, so you will be returned to
        the sign-in screen.
      </p>
    </div>
  );
}
