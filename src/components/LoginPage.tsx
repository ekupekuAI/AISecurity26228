/**
 * Sign-in screen.
 *
 * The left panel states what the platform verifies; the right panel authenticates. Both
 * are honest: the posture strip is fetched live from the node, so it reports what this
 * deployment actually is rather than a fixed marketing claim. If the engine is down, the
 * screen says so before anyone signs in.
 *
 * There is deliberately no "continue without signing in" path.
 */

import React, { useEffect, useState } from 'react';
import { motion, useMotionValue, useSpring, useTransform } from 'motion/react';
import { Eye, Fingerprint, KeyRound, LogIn, Lock, ScanLine, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext.js';
import { Badge, Button, Spinner, cn } from '../ui/primitives.js';

interface NodeHealth {
  status: string;
  demoMode: boolean;
  engine: { status: string };
}

const PILLARS = [
  {
    icon: ScanLine,
    title: 'Training-data integrity',
    body: 'Deduplication, label-flip and trigger detection, OOD scoring — rolled up to per-contributor risk.',
  },
  {
    icon: Fingerprint,
    title: 'Model integrity',
    body: 'Fail-closed pickle audit, weight and graph analysis, trigger inversion backed by a behavioural battery.',
  },
  {
    icon: Lock,
    title: 'Inference provenance',
    body: 'Ed25519 seals binding input, model, preprocessing and output, with replay and substitution defence.',
  },
];

export const LoginPage: React.FC = () => {
  const { login, loginAsObserver, error, clearError } = useAuth();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState<'none' | 'login' | 'observer'>('none');
  const [health, setHealth] = useState<NodeHealth | null>(null);

  useEffect(() => {
    // /api/health is the only endpoint reachable without a session, so it is where the
    // sign-in screen learns the node's posture.
    fetch('/api/health')
      .then((response) => (response.ok ? response.json() : null))
      .then((data) => setHealth(data))
      .catch(() => undefined);
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!identifier.trim() || !password) return;
    setBusy('login');
    try {
      await login(identifier.trim(), password);
    } catch {
      setPassword('');
    } finally {
      setBusy('none');
    }
  };

  const observer = async () => {
    setBusy('observer');
    try {
      await loginAsObserver();
    } catch {
      // The context surfaces the message.
    } finally {
      setBusy('none');
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden">
      <AmbientField />

      <div className="relative z-10 mx-auto grid min-h-screen w-full max-w-7xl grid-cols-1 items-center gap-10 px-5 py-10 lg:grid-cols-[1.05fr_auto] lg:gap-16 lg:px-10">
        <motion.section
          initial={{ opacity: 0, x: -24 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.65, ease: [0.16, 1, 0.3, 1] }}
          className="hidden lg:block"
        >
          <div className="mb-7 flex items-center gap-3">
            <Emblem />
            <div>
              <p className="mono text-[10px] uppercase tracking-[0.22em] text-[var(--color-ink-dim)]">
                SIH 2026 · PS SIH26228
              </p>
              <h1 className="text-[26px] font-bold leading-tight tracking-tight">
                TrustVision
              </h1>
            </div>
          </div>

          <p className="max-w-xl text-[15px] leading-relaxed text-[var(--color-ink-muted)] text-balance">
            An air-gapped inspection layer for multi-contributor computer-vision supply chains. It
            treats every dataset, checkpoint and inference as an untrusted asset, and reports what it
            verified <em className="not-italic text-[var(--color-ink)]">and what it could not</em>.
          </p>

          <div className="mt-8 space-y-3">
            {PILLARS.map((pillar, index) => (
              <motion.div
                key={pillar.title}
                initial={{ opacity: 0, y: 18 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.18 + index * 0.1, ease: [0.16, 1, 0.3, 1] }}
                className="group flex gap-3.5 rounded-xl border border-[var(--color-border)] bg-white/[0.02] p-4 transition-colors duration-200 hover:border-[var(--color-border-strong)] hover:bg-white/[0.04]"
              >
                <span className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--color-surface-2)] text-[var(--color-accent-bright)] ring-1 ring-inset ring-white/5 transition-transform duration-300 group-hover:scale-110">
                  <pillar.icon size={16} />
                </span>
                <div>
                  <p className="text-[13px] font-semibold">{pillar.title}</p>
                  <p className="mt-1 text-[12px] leading-relaxed text-[var(--color-ink-muted)]">{pillar.body}</p>
                </div>
              </motion.div>
            ))}
          </div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6, duration: 0.5 }}
            className="mono mt-7 flex flex-wrap items-center gap-x-5 gap-y-2 text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)]"
          >
            <span>Ministry of Defence · Indian Army (DGIS)</span>
            <span className="text-[var(--color-border-strong)]">|</span>
            <span>Zero external network dependency</span>
          </motion.div>
        </motion.section>

        <motion.section
          initial={{ opacity: 0, y: 28, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="mx-auto w-full max-w-[420px]"
        >
          <div className="glass relative overflow-hidden rounded-2xl p-7 shadow-[0_40px_120px_-40px_rgba(0,0,0,0.9)]">
            <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-blue-400/45 to-transparent" />

            <div className="mb-6 lg:hidden">
              <Emblem />
            </div>

            <h2 className="text-lg font-bold tracking-tight">Analyst sign-in</h2>
            <p className="mono mt-1 text-[10px] uppercase tracking-[0.18em] text-[var(--color-ink-dim)]">
              Clearance verification required
            </p>

            {error && (
              <motion.div
                initial={{ opacity: 0, height: 0, marginTop: 0 }}
                animate={{ opacity: 1, height: 'auto', marginTop: 20 }}
                className="overflow-hidden"
              >
                <div className="flex items-start gap-2.5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3.5 py-2.5">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-rose-400" />
                  <p className="flex-1 text-[12px] leading-relaxed text-rose-200">{error}</p>
                  <button
                    onClick={clearError}
                    className="text-rose-300/60 transition-colors hover:text-rose-200"
                    aria-label="Dismiss"
                  >
                    ×
                  </button>
                </div>
              </motion.div>
            )}

            <form onSubmit={submit} className="mt-6 space-y-4">
              <Field
                label="Analyst identifier"
                value={identifier}
                onChange={setIdentifier}
                placeholder="username or email"
                autoComplete="username"
                autoFocus
                disabled={busy !== 'none'}
              />
              <Field
                label="Security key"
                value={password}
                onChange={setPassword}
                type="password"
                placeholder="••••••••••••"
                autoComplete="current-password"
                disabled={busy !== 'none'}
              />

              <Button
                type="submit"
                variant="primary"
                size="lg"
                className="w-full"
                loading={busy === 'login'}
                icon={busy === 'login' ? undefined : <LogIn size={17} />}
                disabled={busy !== 'none' || !identifier.trim() || !password}
              >
                {busy === 'login' ? 'Verifying clearance' : 'Sign in'}
              </Button>
            </form>

            {health?.demoMode && (
              <>
                <div className="my-6 flex items-center gap-3">
                  <span className="h-px flex-1 bg-[var(--color-border)]" />
                  <span className="mono text-[10px] uppercase tracking-[0.18em] text-[var(--color-ink-dim)]">
                    evaluation
                  </span>
                  <span className="h-px flex-1 bg-[var(--color-border)]" />
                </div>

                <Button
                  onClick={observer}
                  variant="secondary"
                  size="lg"
                  className="w-full"
                  loading={busy === 'observer'}
                  icon={busy === 'observer' ? undefined : <Eye size={17} />}
                  disabled={busy !== 'none'}
                >
                  Read-only evaluation session
                </Button>
                <p className="mt-2.5 text-[11px] leading-relaxed text-[var(--color-ink-dim)]">
                  Observer role: no analysis, sealing or configuration rights. Every use is written to
                  the audit ledger. Unavailable on a production node.
                </p>
              </>
            )}

            <div className="mt-6 flex items-start gap-2.5 border-t border-[var(--color-border)] pt-5">
              <KeyRound size={13} className="mt-0.5 shrink-0 text-[var(--color-ink-dim)]" />
              <p className="text-[11px] leading-relaxed text-[var(--color-ink-dim)]">
                First boot prints a one-time administrator credential to the server console. Set{' '}
                <code className="mono rounded bg-white/5 px-1 py-0.5 text-[10px] text-[var(--color-ink-muted)]">
                  AIA_BOOTSTRAP_USER
                </code>{' '}
                and{' '}
                <code className="mono rounded bg-white/5 px-1 py-0.5 text-[10px] text-[var(--color-ink-muted)]">
                  AIA_BOOTSTRAP_PASSWORD
                </code>{' '}
                to control it. There is no default password.
              </p>
            </div>
          </div>

          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.45, duration: 0.5 }}
            className="mt-4 flex flex-wrap items-center justify-center gap-2"
          >
            {health ? (
              <>
                <Badge tone={health.engine.status === 'ONLINE' ? 'ok' : 'warn'} pulse>
                  engine {health.engine.status.toLowerCase()}
                </Badge>
                <Badge tone="accent">air-gapped</Badge>
                {health.demoMode && <Badge tone="warn">demo mode</Badge>}
              </>
            ) : (
              <Badge tone="neutral">
                <Spinner className="h-2.5 w-2.5" /> contacting node
              </Badge>
            )}
          </motion.div>
        </motion.section>
      </div>
    </div>
  );
};

/* ----------------------------------------------------------------- pieces */

function Field({
  label,
  value,
  onChange,
  type = 'text',
  placeholder,
  autoComplete,
  autoFocus,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  autoComplete?: string;
  autoFocus?: boolean;
  disabled?: boolean;
}) {
  const [focused, setFocused] = useState(false);

  return (
    <label className="block">
      <span className="mono mb-1.5 block text-[10px] uppercase tracking-[0.16em] text-[var(--color-ink-dim)]">
        {label}
      </span>
      <div
        className={cn(
          'relative rounded-xl border bg-[var(--color-surface-0)]/70 transition-all duration-200',
          focused
            ? 'border-blue-500/60 shadow-[0_0_0_3px_rgba(59,130,246,0.12)]'
            : 'border-[var(--color-border-strong)]'
        )}
      >
        <input
          type={type}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder={placeholder}
          autoComplete={autoComplete}
          autoFocus={autoFocus}
          disabled={disabled}
          className="w-full bg-transparent px-3.5 py-2.5 text-[13px] text-[var(--color-ink)] outline-none placeholder:text-[var(--color-ink-dim)]/60 disabled:opacity-50"
        />
      </div>
    </label>
  );
}

function Emblem() {
  return (
    <motion.div
      initial={{ rotate: -8, scale: 0.9, opacity: 0 }}
      animate={{ rotate: 0, scale: 1, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 220, damping: 18 }}
      className="relative grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-[#1d4ed8] to-[#0e7490] text-white shadow-[0_10px_30px_-10px_rgba(29,78,216,0.85)]"
    >
      <ShieldCheck size={24} />
      <span className="absolute inset-0 rounded-xl ring-1 ring-inset ring-white/20" />
    </motion.div>
  );
}

/**
 * Parallax ambience.
 *
 * Three layers drift against the pointer at different rates, which the eye reads as
 * depth. Everything is driven through springs on `transform` only, so the effect stays on
 * the compositor and costs nothing measurable.
 */
function AmbientField() {
  const pointerX = useMotionValue(0);
  const pointerY = useMotionValue(0);

  const spring = { stiffness: 60, damping: 22, mass: 0.8 };
  const sx = useSpring(pointerX, spring);
  const sy = useSpring(pointerY, spring);

  const nearX = useTransform(sx, [-0.5, 0.5], [28, -28]);
  const nearY = useTransform(sy, [-0.5, 0.5], [22, -22]);
  const midX = useTransform(sx, [-0.5, 0.5], [16, -16]);
  const midY = useTransform(sy, [-0.5, 0.5], [12, -12]);
  const farX = useTransform(sx, [-0.5, 0.5], [7, -7]);
  const farY = useTransform(sy, [-0.5, 0.5], [5, -5]);

  useEffect(() => {
    const handle = (event: PointerEvent) => {
      pointerX.set(event.clientX / window.innerWidth - 0.5);
      pointerY.set(event.clientY / window.innerHeight - 0.5);
    };
    window.addEventListener('pointermove', handle, { passive: true });
    return () => window.removeEventListener('pointermove', handle);
  }, [pointerX, pointerY]);

  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden>
      <motion.div
        style={{ x: farX, y: farY }}
        className="absolute -left-40 -top-40 h-[34rem] w-[34rem] rounded-full bg-blue-600/14 blur-[110px]"
      />
      <motion.div
        style={{ x: midX, y: midY }}
        className="absolute -right-32 top-1/4 h-[28rem] w-[28rem] rounded-full bg-cyan-500/10 blur-[100px]"
      />
      <motion.div
        style={{ x: nearX, y: nearY }}
        className="absolute bottom-[-12rem] left-1/3 h-[30rem] w-[30rem] rounded-full bg-blue-500/10 blur-[110px]"
      />

      {/* A slow sweep, suggesting an instrument actively looking at something. */}
      <div className="absolute inset-x-0 top-0 h-32 overflow-hidden opacity-45">
        <div className="animate-scan h-16 w-full bg-gradient-to-b from-transparent via-blue-400/9 to-transparent" />
      </div>
    </div>
  );
}
