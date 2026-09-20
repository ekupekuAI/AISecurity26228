/**
 * Analytics.
 *
 * The tables elsewhere carry the authoritative numbers; this page is for reading the shape
 * of them at a glance — how risk has moved across assessments, where the composite score
 * comes from, and how findings and verdicts are distributed. Every series is read from the
 * node's own records; there is no sample data, so an empty node shows empty charts.
 */

import React, { useEffect, useMemo, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Activity, BarChart3, Gauge, PieChart as PieIcon } from 'lucide-react';
import type { Finding, PlatformStats } from '../../types.js';
import { listAnalyses, listFindings } from '../../api/client.js';
import { Card, CardHeader, EmptyState } from '../../ui/primitives.js';
import type { PageProps } from './shared.js';

interface AnalyticsProps extends PageProps {
  stats: PlatformStats | null;
  loading: boolean;
}

const AXIS = '#7789a8';
const GRID = 'rgba(255,255,255,0.06)';
const BLUE = '#3b82f6';

function bandColor(risk: number): string {
  return risk >= 70 ? '#f43f5e' : risk >= 30 ? '#f59e0b' : '#10b981';
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#f43f5e',
  HIGH: '#fb923c',
  MEDIUM: '#f59e0b',
  LOW: '#38bdf8',
  INFO: '#94a3b8',
};

const STATUS_COLOR: Record<string, string> = {
  DETECTED: '#f43f5e',
  SUSPICIOUS: '#f59e0b',
  'NOT DETECTED': '#10b981',
  DEGRADED: '#94a3b8',
};

export const AnalyticsPage: React.FC<AnalyticsProps> = ({ stats, loading }) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [analyses, setAnalyses] = useState<PlatformStats['recentAnalyses']>([]);

  useEffect(() => {
    listFindings(500)
      .then(setFindings)
      .catch(() => setFindings([]));
    // The full analysis history, not stats.recentAnalyses (capped at 10) — otherwise the risk
    // trend and verdict distribution would silently reflect only the last 10 assessments while
    // claiming to cover every one.
    listAnalyses(500)
      .then(setAnalyses)
      .catch(() => setAnalyses([]));
  }, [stats]);

  const trend = useMemo(
    () =>
      [...analyses].reverse().map((analysis, index) => ({
        i: index + 1,
        risk: Math.round(analysis.risk * 10) / 10,
        name: analysis.name,
        type: analysis.type,
        status: analysis.status,
      })),
    [analyses]
  );

  const pillars = useMemo(
    () => [
      { name: 'Dataset', risk: Math.round((stats?.datasetRisk ?? 0) * 10) / 10 },
      { name: 'Model', risk: Math.round((stats?.modelRisk ?? 0) * 10) / 10 },
      { name: 'Inference', risk: Math.round((stats?.inferenceIntegrityRisk ?? 0) * 10) / 10 },
      { name: 'Shift', risk: Math.round((stats?.distributionShiftRisk ?? 0) * 10) / 10 },
    ],
    [stats]
  );

  const statusData = useMemo(() => {
    const counts = new Map<string, number>();
    for (const analysis of analyses) counts.set(analysis.status, (counts.get(analysis.status) ?? 0) + 1);
    return [...counts.entries()].map(([name, value]) => ({ name, value }));
  }, [analyses]);

  const severityData = useMemo(() => {
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const counts = new Map<string, number>();
    for (const finding of findings) counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
    return order.filter((key) => counts.has(key)).map((name) => ({ name, value: counts.get(name) ?? 0 }));
  }, [findings]);

  const hasData = analyses.length > 0;

  if (loading && !stats) {
    return (
      <Card>
        <EmptyState icon={<BarChart3 size={22} />} title="Loading analytics…" />
      </Card>
    );
  }

  if (!hasData) {
    return (
      <Card>
        <EmptyState
          icon={<BarChart3 size={22} />}
          title="No assessments to chart yet"
          description="Submit a dataset or a model. As assessments accumulate, their risk trend and score breakdowns are drawn here."
        />
      </Card>
    );
  }

  return (
    <div className="space-y-5">
      {/* Risk trend across assessments */}
      <Card>
        <CardHeader
          title="Risk trend"
          subtitle="Composite risk score of each completed assessment, oldest to newest. The amber line marks the REVIEW threshold (30) and the red line the QUARANTINE threshold (70)."
          icon={<Activity size={15} />}
        />
        <div className="px-3 pb-4 pt-1">
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={trend} margin={{ top: 8, right: 16, bottom: 4, left: -8 }}>
              <CartesianGrid stroke={GRID} vertical={false} />
              <XAxis
                dataKey="i"
                tick={{ fill: AXIS, fontSize: 11 }}
                tickLine={false}
                axisLine={{ stroke: GRID }}
                label={{ value: 'assessment', position: 'insideBottom', offset: -2, fill: AXIS, fontSize: 10 }}
              />
              <YAxis
                domain={[0, 100]}
                tick={{ fill: AXIS, fontSize: 11 }}
                tickLine={false}
                axisLine={{ stroke: GRID }}
                width={40}
              />
              <ReferenceLine y={30} stroke="#f59e0b" strokeDasharray="4 4" strokeOpacity={0.5} />
              <ReferenceLine y={70} stroke="#f43f5e" strokeDasharray="4 4" strokeOpacity={0.5} />
              <Tooltip content={<TrendTooltip />} cursor={{ stroke: BLUE, strokeOpacity: 0.3 }} />
              <Line
                type="monotone"
                dataKey="risk"
                stroke={BLUE}
                strokeWidth={2}
                dot={<TrendDot />}
                activeDot={{ r: 5 }}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Composite score breakdown */}
        <Card>
          <CardHeader
            title="Score breakdown by pillar"
            subtitle="Where the node's composite risk comes from: dataset and model each weigh 0.35, inference and distribution shift 0.15."
            icon={<Gauge size={15} />}
          />
          <div className="px-3 pb-4 pt-1">
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={pillars} margin={{ top: 8, right: 16, bottom: 4, left: -8 }}>
                <CartesianGrid stroke={GRID} vertical={false} />
                <XAxis dataKey="name" tick={{ fill: AXIS, fontSize: 11 }} tickLine={false} axisLine={{ stroke: GRID }} />
                <YAxis domain={[0, 100]} tick={{ fill: AXIS, fontSize: 11 }} tickLine={false} axisLine={{ stroke: GRID }} width={40} />
                <Tooltip content={<PillarTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                <Bar dataKey="risk" radius={[4, 4, 0, 0]} isAnimationActive={false}>
                  {pillars.map((pillar) => (
                    <Cell key={pillar.name} fill={bandColor(pillar.risk)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Verdict distribution */}
        <Card>
          <CardHeader
            title="Verdict distribution"
            subtitle="How every assessment on this node was classified: NOT DETECTED, SUSPICIOUS or DETECTED."
            icon={<PieIcon size={15} />}
          />
          <div className="flex items-center justify-center px-3 pb-4 pt-1">
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={statusData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={58}
                  outerRadius={92}
                  paddingAngle={2}
                  stroke="none"
                  isAnimationActive={false}
                >
                  {statusData.map((entry) => (
                    <Cell key={entry.name} fill={STATUS_COLOR[entry.name] ?? '#94a3b8'} />
                  ))}
                </Pie>
                <Tooltip content={<CountTooltip suffix="assessments" />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <Legend items={statusData.map((entry) => ({ label: entry.name, color: STATUS_COLOR[entry.name] ?? '#94a3b8' }))} />
        </Card>
      </div>

      {/* Findings by severity */}
      <Card>
        <CardHeader
          title="Findings by severity"
          subtitle="Every finding raised across all assessments, bucketed by severity."
          icon={<BarChart3 size={15} />}
        />
        <div className="px-3 pb-4 pt-1">
          {severityData.length === 0 ? (
            <EmptyState icon={<BarChart3 size={20} />} title="No findings raised" />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={severityData} layout="vertical" margin={{ top: 4, right: 24, bottom: 4, left: 12 }}>
                <CartesianGrid stroke={GRID} horizontal={false} />
                <XAxis type="number" tick={{ fill: AXIS, fontSize: 11 }} tickLine={false} axisLine={{ stroke: GRID }} allowDecimals={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: AXIS, fontSize: 11 }} tickLine={false} axisLine={{ stroke: GRID }} width={72} />
                <Tooltip content={<CountTooltip suffix="findings" />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} isAnimationActive={false}>
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLOR[entry.name] ?? '#94a3b8'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </Card>
    </div>
  );
};

/* ------------------------------------------------------------------ pieces */

function TrendDot(props: { cx?: number; cy?: number; payload?: { risk: number } }) {
  const { cx, cy, payload } = props;
  if (cx === undefined || cy === undefined || !payload) return null;
  return <circle cx={cx} cy={cy} r={3.5} fill={bandColor(payload.risk)} stroke="#0b0f17" strokeWidth={1.5} />;
}

function TooltipShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface-2)] px-3 py-2 text-[11px] shadow-2xl">
      {children}
    </div>
  );
}

function TrendTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: { risk: number; name: string; type: string; status: string } }> }) {
  if (!active || !payload?.length) return null;
  const point = payload[0].payload;
  return (
    <TooltipShell>
      <p className="mb-0.5 max-w-[220px] truncate font-semibold text-[var(--color-ink)]">{point.name}</p>
      <p className="mono text-[10px] text-[var(--color-ink-dim)]">{point.type}</p>
      <p className="mono mt-1" style={{ color: bandColor(point.risk) }}>
        risk {point.risk} · {point.status}
      </p>
    </TooltipShell>
  );
}

function PillarTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: { name: string; risk: number } }> }) {
  if (!active || !payload?.length) return null;
  const point = payload[0].payload;
  return (
    <TooltipShell>
      <p className="font-semibold text-[var(--color-ink)]">{point.name}</p>
      <p className="mono mt-0.5" style={{ color: bandColor(point.risk) }}>
        risk {point.risk}/100
      </p>
    </TooltipShell>
  );
}

function CountTooltip({
  active,
  payload,
  suffix,
}: {
  active?: boolean;
  payload?: Array<{ name: string; value: number; payload: { name: string } }>;
  suffix: string;
}) {
  if (!active || !payload?.length) return null;
  const entry = payload[0];
  return (
    <TooltipShell>
      <p className="font-semibold text-[var(--color-ink)]">{entry.payload.name}</p>
      <p className="mono mt-0.5 text-[var(--color-ink-muted)]">
        {entry.value} {suffix}
      </p>
    </TooltipShell>
  );
}

function Legend({ items }: { items: Array<{ label: string; color: string }> }) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1.5 px-5 pb-5">
      {items.map((item) => (
        <span key={item.label} className="mono flex items-center gap-1.5 text-[10px] text-[var(--color-ink-muted)]">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
          {item.label}
        </span>
      ))}
    </div>
  );
}
