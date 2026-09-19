/**
 * Design-system primitives.
 *
 * Built on Tailwind + Radix rather than a component kit, for two reasons that matter
 * here: Radix ships behaviour and accessibility with no styling opinion, so the console
 * can look like an instrument instead of a web app; and the bundle carries only what is
 * actually used.
 *
 * Motion rules applied throughout:
 *  - Only `transform` and `opacity` are animated. Anything else forces layout and the
 *    animation stutters exactly when the interface is busiest.
 *  - Entrances are fast (180-320 ms) and exits faster. Slow UI feels broken, not premium.
 *  - Every interactive element has a pressed state. Without it a click feels ignored.
 *  - `prefers-reduced-motion` is honoured globally in index.css.
 */

import React, { forwardRef, useCallback, useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion, useMotionValue, useSpring, useTransform } from 'motion/react';
import type { HTMLMotionProps } from 'motion/react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { Info } from 'lucide-react';
import type { FindingSeverity } from '../types.js';

export function cn(...inputs: Parameters<typeof clsx>): string {
  return twMerge(clsx(inputs));
}

/* ------------------------------------------------------------------ Button */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'success';
type ButtonSize = 'sm' | 'md' | 'lg';

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'bg-[#1d4ed8] text-white shadow-[0_1px_0_0_rgba(255,255,255,0.14)_inset,0_8px_24px_-8px_rgba(29,78,216,0.7)] hover:bg-[#2563eb]',
  secondary:
    'bg-[var(--color-surface-2)] text-[var(--color-ink)] border border-[var(--color-border-strong)] hover:bg-[var(--color-surface-3)] hover:border-[#3a5480]',
  ghost: 'text-[var(--color-ink-muted)] hover:text-[var(--color-ink)] hover:bg-white/5',
  danger:
    'bg-[#9f1239] text-rose-50 border border-rose-700/60 hover:bg-[#be123c] shadow-[0_8px_24px_-10px_rgba(244,63,94,0.7)]',
  success:
    'bg-[#065f46] text-emerald-50 border border-emerald-700/60 hover:bg-[#047857] shadow-[0_8px_24px_-10px_rgba(16,185,129,0.6)]',
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-xs gap-1.5 rounded-lg',
  md: 'h-10 px-4 text-[13px] gap-2 rounded-xl',
  lg: 'h-12 px-6 text-sm gap-2.5 rounded-xl',
};

export interface ButtonProps extends Omit<HTMLMotionProps<'button'>, 'children'> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: React.ReactNode;
  children?: React.ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', loading, icon, children, className, disabled, ...rest },
  ref
) {
  const isDisabled = disabled || loading;
  return (
    <motion.button
      ref={ref}
      // A slight lift on hover and a real compression on press. The scale values are
      // small deliberately: anything larger reads as a toy.
      whileHover={isDisabled ? undefined : { y: -1 }}
      whileTap={isDisabled ? undefined : { scale: 0.97, y: 0 }}
      transition={{ type: 'spring', stiffness: 600, damping: 30, mass: 0.5 }}
      disabled={isDisabled}
      className={cn(
        'relative inline-flex items-center justify-center font-semibold select-none',
        'transition-colors duration-150 outline-none',
        'disabled:opacity-45 disabled:cursor-not-allowed disabled:pointer-events-none',
        BUTTON_SIZES[size],
        BUTTON_VARIANTS[variant],
        className
      )}
      {...rest}
    >
      {loading ? <Spinner className="shrink-0" /> : icon}
      {children}
    </motion.button>
  );
});

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        'inline-block h-3.5 w-3.5 shrink-0 rounded-full border-2 border-current border-t-transparent animate-spin',
        className
      )}
      role="status"
      aria-label="loading"
    />
  );
}

/* -------------------------------------------------------------------- Card */

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Adds a cursor-tracked 3D tilt. Reserved for hero surfaces; noise everywhere else. */
  tilt?: boolean;
  glow?: boolean;
}

export function Card({ tilt, glow, className, children, ...rest }: CardProps) {
  if (tilt) {
    return (
      <TiltCard className={className} glow={glow} {...rest}>
        {children}
      </TiltCard>
    );
  }
  return (
    <div
      className={cn(
        'panel relative overflow-hidden',
        glow && 'shadow-[0_0_0_1px_rgba(59,130,246,0.12),0_20px_60px_-30px_rgba(59,130,246,0.45)]',
        className
      )}
      {...rest}
    >
      <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/18 to-transparent" />
      {children}
    </div>
  );
}

/**
 * Cursor-tracked perspective tilt.
 *
 * Rotation is capped at 6 degrees. Larger angles distort text and make a data panel
 * harder to read, which defeats the point of the interface.
 */
function TiltCard({ className, glow, children, ...rest }: CardProps) {
  const ref = useRef<HTMLDivElement>(null);
  const x = useMotionValue(0);
  const y = useMotionValue(0);

  const springConfig = { stiffness: 260, damping: 26, mass: 0.6 };
  const rotateX = useSpring(useTransform(y, [-0.5, 0.5], [6, -6]), springConfig);
  const rotateY = useSpring(useTransform(x, [-0.5, 0.5], [-6, 6]), springConfig);

  const handleMove = useCallback(
    (event: React.MouseEvent<HTMLDivElement>) => {
      const bounds = ref.current?.getBoundingClientRect();
      if (!bounds) return;
      x.set((event.clientX - bounds.left) / bounds.width - 0.5);
      y.set((event.clientY - bounds.top) / bounds.height - 0.5);
    },
    [x, y]
  );

  const reset = useCallback(() => {
    x.set(0);
    y.set(0);
  }, [x, y]);

  return (
    <div className="perspective-card" onMouseMove={handleMove} onMouseLeave={reset}>
      <motion.div
        ref={ref}
        style={{ rotateX, rotateY, transformStyle: 'preserve-3d' }}
        className={cn(
          'panel relative overflow-hidden will-change-transform',
          glow && 'shadow-[0_0_0_1px_rgba(59,130,246,0.14),0_28px_70px_-32px_rgba(59,130,246,0.5)]',
          className
        )}
        {...(rest as HTMLMotionProps<'div'>)}
      >
        <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/20 to-transparent" />
        {children}
      </motion.div>
    </div>
  );
}

/**
 * Click-to-reveal information affordance.
 *
 * The default state is minimal: a single small `i` glyph. The explanation only appears
 * when an operator asks for it, so a dense console stays legible until someone wants the
 * detail. Closes on outside click or Escape.
 */
export function InfoHint({
  children,
  label = 'More information',
  align = 'end',
  className,
}: {
  children: React.ReactNode;
  label?: string;
  align?: 'start' | 'end';
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return undefined;
    const onDocDown = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDocDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <span ref={ref} className={cn('relative inline-flex shrink-0 align-middle', className)}>
      <button
        type="button"
        onClick={(event) => {
          event.stopPropagation();
          setOpen((value) => !value);
        }}
        aria-expanded={open}
        aria-label={label}
        className={cn(
          'grid h-[18px] w-[18px] place-items-center rounded-full text-[var(--color-ink-dim)] ring-1 ring-inset ring-white/10 transition-colors',
          'hover:text-[var(--color-ink)] hover:ring-white/25',
          open && 'text-[var(--color-accent-bright)] ring-blue-400/40 bg-blue-500/10'
        )}
      >
        <Info size={11} strokeWidth={2.4} />
      </button>
      <AnimatePresence>
        {open && (
          <motion.span
            role="tooltip"
            initial={{ opacity: 0, y: -4, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.97 }}
            transition={{ duration: 0.16, ease: [0.16, 1, 0.3, 1] }}
            className={cn(
              'absolute top-[26px] z-50 block w-64 rounded-xl border border-[var(--color-border-strong)] bg-[var(--color-surface-2)] p-3 text-[11.5px] font-normal normal-case leading-relaxed tracking-normal text-[var(--color-ink-muted)] shadow-2xl',
              align === 'end' ? 'right-0' : 'left-0'
            )}
          >
            {children}
          </motion.span>
        )}
      </AnimatePresence>
    </span>
  );
}

export function CardHeader({
  title,
  subtitle,
  icon,
  action,
  className,
}: {
  title: React.ReactNode;
  /** Rendered behind a click-to-reveal info glyph, not inline, to keep the header minimal. */
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex items-center justify-between gap-4 px-5 pt-4 pb-3', className)}>
      <div className="flex items-center gap-2.5 min-w-0">
        {icon && (
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-[var(--color-surface-3)] text-[var(--color-accent-bright)] ring-1 ring-inset ring-white/5">
            {icon}
          </span>
        )}
        <h3 className="text-sm font-semibold tracking-tight truncate">{title}</h3>
        {subtitle && <InfoHint>{subtitle}</InfoHint>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------- Badge */

export const SEVERITY_STYLES: Record<FindingSeverity, { chip: string; dot: string; label: string }> = {
  CRITICAL: { chip: 'bg-rose-500/12 text-rose-300 ring-rose-500/30', dot: 'bg-rose-400', label: 'CRITICAL' },
  HIGH: { chip: 'bg-orange-500/12 text-orange-300 ring-orange-500/30', dot: 'bg-orange-400', label: 'HIGH' },
  MEDIUM: { chip: 'bg-amber-500/12 text-amber-300 ring-amber-500/30', dot: 'bg-amber-400', label: 'MEDIUM' },
  LOW: { chip: 'bg-sky-500/12 text-sky-300 ring-sky-500/30', dot: 'bg-sky-400', label: 'LOW' },
  INFO: { chip: 'bg-slate-500/12 text-slate-300 ring-slate-500/30', dot: 'bg-slate-400', label: 'INFO' },
};

export function Badge({
  children,
  tone = 'neutral',
  className,
  pulse,
}: {
  children: React.ReactNode;
  tone?: 'neutral' | 'accent' | 'ok' | 'warn' | 'danger';
  className?: string;
  pulse?: boolean;
}) {
  const tones = {
    neutral: 'bg-white/5 text-[var(--color-ink-muted)] ring-white/10',
    accent: 'bg-blue-500/12 text-blue-300 ring-blue-500/30',
    ok: 'bg-emerald-500/12 text-emerald-300 ring-emerald-500/30',
    warn: 'bg-amber-500/12 text-amber-300 ring-amber-500/30',
    danger: 'bg-rose-500/12 text-rose-300 ring-rose-500/30',
  } as const;

  return (
    <span
      className={cn(
        'mono inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ring-1 ring-inset',
        tones[tone],
        className
      )}
    >
      {pulse && <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse-ring" />}
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: FindingSeverity; className?: string }) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.INFO;
  return (
    <span
      className={cn(
        'mono inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ring-1 ring-inset',
        style.chip,
        className
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', style.dot)} />
      {style.label}
    </span>
  );
}

/* ---------------------------------------------------------------- Progress */

/**
 * Risk meter.
 *
 * Colour is bound to the governance bands, not to the raw number, so the bar and the
 * decision can never tell different stories.
 */
export function RiskBar({
  value,
  className,
  showBands = false,
}: {
  value: number;
  className?: string;
  showBands?: boolean;
}) {
  const clamped = Math.max(0, Math.min(100, value));
  const tone = clamped >= 70 ? 'bg-rose-500' : clamped >= 30 ? 'bg-amber-500' : 'bg-emerald-500';

  return (
    <div className={cn('relative h-1.5 w-full overflow-hidden rounded-full bg-white/7', className)}>
      {showBands && (
        <>
          <span className="absolute left-[30%] top-0 h-full w-px bg-white/20" aria-hidden />
          <span className="absolute left-[70%] top-0 h-full w-px bg-white/20" aria-hidden />
        </>
      )}
      <motion.span
        className={cn('absolute inset-y-0 left-0 rounded-full', tone)}
        initial={{ width: 0 }}
        animate={{ width: `${clamped}%` }}
        transition={{ duration: 0.75, ease: [0.16, 1, 0.3, 1] }}
      />
    </div>
  );
}

/* ----------------------------------------------------------------- Motion */

/**
 * Scroll-triggered entrance.
 *
 * `whileInView` alone is not safe for page-sized content. A fast scroll -- a flung
 * trackpad, an anchor jump, a restored scroll position -- reports only the final
 * intersection state, so a section the viewport passed *over* never fires and stays at
 * opacity 0 until the reader happens to scroll back to it. On a reference page that is
 * indistinguishable from the content being missing.
 *
 * So the observer is the fast path, and a scroll listener force-shows anything the
 * viewport has already passed. The effect is unchanged for ordinary reading; the failure
 * mode is simply that content is visible, which is the correct way for this to fail.
 */
export function Reveal({
  children,
  delay = 0,
  y = 16,
  className,
}: {
  children: React.ReactNode;
  delay?: number;
  y?: number;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    if (shown) return undefined;

    const element = ref.current;
    if (!element) return undefined;

    const settle = () => {
      const bounds = element.getBoundingClientRect();
      // Visible, or already scrolled past. Either way it must not stay hidden.
      if (bounds.top < window.innerHeight - 60 || bounds.bottom < 0) setShown(true);
    };

    settle();
    window.addEventListener('scroll', settle, { passive: true });
    window.addEventListener('resize', settle, { passive: true });
    return () => {
      window.removeEventListener('scroll', settle);
      window.removeEventListener('resize', settle);
    };
  }, [shown]);

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y }}
      animate={shown ? { opacity: 1, y: 0 } : { opacity: 0, y }}
      transition={{ duration: 0.45, delay, ease: [0.16, 1, 0.3, 1] }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/** Staggered container. Children should be `<Stagger.Item>`. */
export function Stagger({
  children,
  className,
  step = 0.05,
}: {
  children: React.ReactNode;
  className?: string;
  step?: number;
}) {
  return (
    <motion.div
      initial="hidden"
      animate="show"
      variants={{ hidden: {}, show: { transition: { staggerChildren: step } } }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

Stagger.Item = function StaggerItem({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <motion.div
      variants={{
        hidden: { opacity: 0, y: 14 },
        show: { opacity: 1, y: 0, transition: { duration: 0.4, ease: [0.16, 1, 0.3, 1] } },
      }}
      className={className}
    >
      {children}
    </motion.div>
  );
};

/* ------------------------------------------------------------------ States */

export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'animate-shimmer rounded-lg bg-gradient-to-r from-white/4 via-white/9 to-white/4',
        className
      )}
    />
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      {icon && (
        <span className="grid h-12 w-12 place-items-center rounded-xl bg-[var(--color-surface-2)] text-[var(--color-ink-dim)] ring-1 ring-inset ring-white/5">
          {icon}
        </span>
      )}
      <div>
        <p className="text-sm font-semibold">{title}</p>
        {description && (
          <p className="mx-auto mt-1 max-w-sm text-xs leading-relaxed text-[var(--color-ink-muted)]">
            {description}
          </p>
        )}
      </div>
      {action}
    </div>
  );
}

/* ------------------------------------------------------------------ Values */

/** Monospaced digest with copy-to-clipboard. Hashes are read character by character. */
export function Hash({ value, chars = 16, className }: { value: string; chars?: number; className?: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      // Clipboard access can be denied; the value is still shown in full on hover.
    }
  };

  return (
    <button
      type="button"
      onClick={copy}
      title={value}
      className={cn(
        'mono group inline-flex items-center gap-1.5 rounded text-[11px] text-[var(--color-ink-muted)] transition-colors hover:text-[var(--color-ink)]',
        className
      )}
    >
      <span className="truncate">{value.length > chars ? `${value.slice(0, chars)}…` : value}</span>
      <span className={cn('text-[9px] transition-opacity', copied ? 'text-emerald-400 opacity-100' : 'opacity-0 group-hover:opacity-60')}>
        {copied ? 'copied' : 'copy'}
      </span>
    </button>
  );
}

/** Animated integer. Movement draws the eye to a number that actually changed. */
export function Counter({
  value,
  decimals = 0,
  className,
}: {
  value: number;
  decimals?: number;
  className?: string;
}) {
  const [display, setDisplay] = useState(0);
  const previous = useRef(0);

  React.useEffect(() => {
    const from = previous.current;
    const to = Number.isFinite(value) ? value : 0;
    previous.current = to;

    const duration = 650;
    const start = performance.now();
    let frame = 0;

    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration);
      // Ease-out cubic: fast initial movement, gentle settle.
      const eased = 1 - (1 - progress) ** 3;
      setDisplay(from + (to - from) * eased);
      if (progress < 1) frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [value]);

  return <span className={className}>{display.toFixed(decimals)}</span>;
}

/* ------------------------------------------------------------------- Toast */

export interface ToastMessage {
  id: number;
  tone: 'ok' | 'error' | 'info';
  title: string;
  detail?: string;
}

export function ToastStack({ toasts, onDismiss }: { toasts: ToastMessage[]; onDismiss: (id: number) => void }) {
  return (
    <div className="pointer-events-none fixed bottom-5 left-1/2 z-[80] flex w-[min(92vw,560px)] -translate-x-1/2 flex-col gap-2">
      <AnimatePresence initial={false}>
        {toasts.map((toast) => (
          <motion.div
            key={toast.id}
            layout
            initial={{ opacity: 0, y: 24, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.97 }}
            transition={{ type: 'spring', stiffness: 420, damping: 32 }}
            className={cn(
              'glass pointer-events-auto flex items-start gap-3 rounded-xl px-4 py-3 shadow-2xl',
              toast.tone === 'ok' && 'ring-1 ring-emerald-500/25',
              toast.tone === 'error' && 'ring-1 ring-rose-500/25',
              toast.tone === 'info' && 'ring-1 ring-blue-500/25'
            )}
          >
            <span
              className={cn(
                'mt-1.5 h-2 w-2 shrink-0 rounded-full',
                toast.tone === 'ok' && 'bg-emerald-400',
                toast.tone === 'error' && 'bg-rose-400',
                toast.tone === 'info' && 'bg-blue-400'
              )}
            />
            <div className="min-w-0 flex-1">
              <p className="text-[13px] font-semibold">{toast.title}</p>
              {toast.detail && (
                <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--color-ink-muted)]">{toast.detail}</p>
              )}
            </div>
            <button
              onClick={() => onDismiss(toast.id)}
              className="shrink-0 text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink)]"
              aria-label="Dismiss"
            >
              ×
            </button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

export { AnimatePresence, motion };
