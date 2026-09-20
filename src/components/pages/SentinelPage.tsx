/**
 * Sentinel -- live monitoring.
 *
 * Deliberately plain: what each agent is, whether it is calm or alarmed, and a running
 * feed of what has been flagged. No dense descriptions. The detail lives elsewhere; this
 * page answers one question at a glance -- is anything wrong right now?
 */

import React, { useCallback, useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  Activity,
  Boxes,
  KeyRound,
  Radar,
  RefreshCw,
  ScrollText,
  Server,
  ShieldAlert,
  ShieldCheck,
  Waves,
} from 'lucide-react';
import type { FindingSeverity, SensorId, SensorStatus, SentinelStatus, SentinelThreat } from '../../types.js';
import { fetchSentinelStatus, fetchSentinelThreats, triggerSentinelSweep } from '../../api/client.js';
import { Badge, Button, Card, CardHeader, EmptyState, SeverityBadge, cn } from '../../ui/primitives.js';
import type { PageProps } from './shared.js';

const SENSOR_ICON: Record<SensorId, React.ReactNode> = {
  auth: <KeyRound size={16} />,
  provenance: <ShieldCheck size={16} />,
  ledger: <ScrollText size={16} />,
  supply_chain: <Boxes size={16} />,
  traffic: <Waves size={16} />,
  operations: <Server size={16} />,
};

const STATUS_STYLE: Record<SensorStatus, { tone: string; ring: string; dot: string; label: string }> = {
  ALERT: { tone: 'text-rose-300', ring: 'ring-rose-500/30', dot: 'bg-rose-400', label: 'Alert' },
  ELEVATED: { tone: 'text-amber-300', ring: 'ring-amber-500/30', dot: 'bg-amber-400', label: 'Elevated' },
  CALIBRATING: { tone: 'text-slate-300', ring: 'ring-slate-500/25', dot: 'bg-slate-400', label: 'Calibrating' },
  NOMINAL: { tone: 'text-emerald-300', ring: 'ring-emerald-500/25', dot: 'bg-emerald-400', label: 'Nominal' },
};

export const SentinelPage: React.FC<PageProps> = ({ pushToast }) => {
  const [status, setStatus] = useState<SentinelStatus | null>(null);
  const [threats, setThreats] = useState<SentinelThreat[]>([]);
  const [loading, setLoading] = useState(true);
  const [sweeping, setSweeping] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, t] = await Promise.all([fetchSentinelStatus(), fetchSentinelThreats(60)]);
      setStatus(s);
      setThreats(t);
      setError(null);
    } catch (e) {
      // A 401 is handled globally by the shell (it signs the operator out). Anything else
      // means the monitor data could not be loaded, which must be shown as a fault rather
      // than hidden behind a green "all clear".
      setError(e instanceof Error ? e.message : 'Live monitoring data is unavailable.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    // The agents sweep on their own timer; the page follows a little behind them.
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, [load]);

  const sweepNow = async () => {
    setSweeping(true);
    try {
      await triggerSentinelSweep();
      await load();
      pushToast('ok', 'Sweep complete', 'All agents re-checked the system.');
    } catch (error) {
      pushToast('error', 'Sweep failed', error instanceof Error ? error.message : undefined);
    } finally {
      setSweeping(false);
    }
  };

  const alerts = status?.counts.alerts ?? 0;
  const elevated = status?.counts.elevated ?? 0;
  const overall: SensorStatus = alerts > 0 ? 'ALERT' : elevated > 0 ? 'ELEVATED' : 'NOMINAL';
  const overallStyle = STATUS_STYLE[overall];
  // A failed fetch must never render as a green "all clear": if we have no status and an
  // error, the monitor itself is down and we say so.
  const monitorDown = Boolean(error) && !status;

  return (
    <div className="space-y-5">
      {monitorDown && (
        <Card className="ring-1 ring-rose-500/30">
          <div className="flex flex-wrap items-center gap-4 p-5">
            <span className="grid h-14 w-14 shrink-0 place-items-center rounded-2xl bg-[var(--color-surface-0)]/60 text-rose-300 ring-1 ring-inset ring-rose-500/30">
              <ShieldAlert size={24} />
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-xl font-bold tracking-tight text-rose-300">Live monitoring unavailable</p>
              <p className="mono mt-1 text-[11px] text-[var(--color-ink-dim)]">
                {error} — the gateway or a sensor did not respond. This is not an “all clear”.
              </p>
            </div>
            <Button onClick={sweepNow} loading={sweeping} icon={sweeping ? undefined : <RefreshCw size={15} />}>
              Retry
            </Button>
          </div>
        </Card>
      )}

      {/* Overall posture */}
      {!monitorDown && (
      <Card glow className={cn('ring-1', overallStyle.ring)}>
        <div className="flex flex-wrap items-center gap-4 p-5">
          <motion.span
            animate={{ scale: overall === 'NOMINAL' ? 1 : [1, 1.08, 1] }}
            transition={overall === 'NOMINAL' ? undefined : { duration: 1.6, repeat: Infinity }}
            className={cn(
              'grid h-14 w-14 shrink-0 place-items-center rounded-2xl bg-[var(--color-surface-0)]/60 ring-1 ring-inset',
              overallStyle.ring,
              overallStyle.tone
            )}
          >
            {overall === 'ALERT' ? <ShieldAlert size={24} /> : <Radar size={24} />}
          </motion.span>

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <p className={cn('text-xl font-bold tracking-tight', overallStyle.tone)}>
                {alerts > 0
                  ? `${alerts} agent${alerts > 1 ? 's' : ''} in alert`
                  : elevated > 0
                    ? `${elevated} agent${elevated > 1 ? 's' : ''} elevated`
                    : 'All clear'}
              </p>
              <Badge tone={status?.running ? 'ok' : 'warn'} pulse={status?.running}>
                {status?.running ? 'monitoring live' : 'stopped'}
              </Badge>
            </div>
            <p className="mono mt-1 text-[11px] text-[var(--color-ink-dim)]">
              {status
                ? `${status.sensors.length} agents · sweep every ${status.intervalSeconds}s · ${status.windowMinutes}-min window`
                : 'connecting to agents…'}
              {status?.lastSweepAt ? ` · last ${new Date(status.lastSweepAt).toLocaleTimeString()}` : ''}
            </p>
          </div>

          <Button onClick={sweepNow} loading={sweeping} icon={sweeping ? undefined : <RefreshCw size={15} />}>
            Sweep now
          </Button>
        </div>

        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-[var(--color-border)] px-5 py-3">
          <Count label="alerts" value={alerts} tone={alerts > 0 ? 'text-rose-400' : undefined} />
          <Count label="elevated" value={elevated} tone={elevated > 0 ? 'text-amber-400' : undefined} />
          <Count label="nominal" value={status?.counts.nominal ?? 0} tone="text-emerald-400" />
          <Count label="calibrating" value={status?.counts.calibrating ?? 0} />
        </div>
      </Card>
      )}

      {/* Agent cards */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {loading && !status
          ? Array.from({ length: 5 }).map((_, i) => (
              <Card key={i} className="h-32 animate-pulse-ring" />
            ))
          : status?.sensors.map((sensor) => {
              const st = STATUS_STYLE[sensor.status];
              return (
                <motion.div
                  key={sensor.sensor}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={cn('panel relative overflow-hidden p-4 ring-1', st.ring)}
                >
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-2.5">
                      <span className={cn('grid h-9 w-9 place-items-center rounded-lg bg-[var(--color-surface-3)] ring-1 ring-inset ring-white/5', st.tone)}>
                        {SENSOR_ICON[sensor.sensor]}
                      </span>
                      <span className="text-[13px] font-semibold">{sensor.label}</span>
                    </span>
                    <span className={cn('mono inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider', st.tone)}>
                      <span className={cn('h-1.5 w-1.5 rounded-full', st.dot, sensor.status !== 'NOMINAL' && 'animate-pulse')} />
                      {st.label}
                    </span>
                  </div>

                  <p className="mt-3 line-clamp-2 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                    {sensor.summary}
                  </p>

                  <div className="mono mt-3 flex items-center gap-4 text-[10px] text-[var(--color-ink-dim)]">
                    <span>now {sensor.signal}</span>
                    <span>baseline {sensor.baseline}</span>
                    {sensor.status !== 'CALIBRATING' && sensor.deviation !== 0 && (
                      <span className={sensor.deviation >= 2 ? 'text-amber-400' : ''}>
                        {sensor.deviation > 0 ? '+' : ''}
                        {sensor.deviation}σ
                      </span>
                    )}
                    {sensor.status === 'CALIBRATING' && <span>learning ({sensor.samples})</span>}
                  </div>
                </motion.div>
              );
            })}
      </div>

      {/* Threat feed */}
      <Card>
        <CardHeader
          title="What the agents have flagged"
          subtitle="Most recent elevated and alert observations. Nominal sweeps are not listed."
          icon={<Activity size={15} />}
          action={
            <button
              onClick={load}
              className="mono flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink)]"
            >
              <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> refresh
            </button>
          }
        />
        <div className="px-2 pb-3">
          {threats.length === 0 ? (
            <EmptyState
              icon={<ShieldCheck size={20} />}
              title="Nothing flagged"
              description="Every agent sweep has come back clean. Flags appear here the moment one does not."
            />
          ) : (
            <ul className="space-y-1">
              <AnimatePresence initial={false}>
                {threats.map((threat) => (
                  <motion.li
                    key={threat.id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="flex items-start gap-3 rounded-xl px-3 py-2.5 transition-colors hover:bg-white/[0.03]"
                  >
                    <span className="mt-0.5 shrink-0">
                      <SeverityBadge severity={threat.severity as FindingSeverity} />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-baseline gap-x-2">
                        <span className="text-[12px] font-medium">{threat.label}</span>
                        <span className="mono text-[10px] text-[var(--color-ink-dim)]">
                          {new Date(threat.observedAt).toLocaleString()}
                        </span>
                      </span>
                      <span className="mt-0.5 block text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                        {threat.summary}
                      </span>
                    </span>
                  </motion.li>
                ))}
              </AnimatePresence>
            </ul>
          )}
        </div>
      </Card>
    </div>
  );
};

function Count({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className={cn('mono text-lg font-bold', tone)}>{value}</span>
      <span className="mono text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)]">{label}</span>
    </div>
  );
}
