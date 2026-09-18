/**
 * Distribution shift: has the operational stream moved, and if so, why?
 *
 * The engine answers with MMD under an RBF kernel plus an attribution step. This page has
 * to supply it with *real* feature vectors, and there are only two honest ways to get
 * them inside an air-gapped console:
 *
 *   1. The analyst's own pipeline exports embeddings. Post them to the API directly.
 *   2. The analyst has the imagery. We measure it here, in the browser, on canvas.
 *
 * Option 2 computes nine named photometric and texture descriptors per image from the
 * actual pixels. They are genuine measurements of the analyst's files — not a synthetic
 * sample, and not a stand-in for backbone embeddings, which is stated on the page because
 * it materially limits what the MMD result means.
 */

import React, { useCallback, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  Activity,
  AlertTriangle,
  CloudSun,
  Crosshair,
  FileJson,
  Images,
  Layers,
  ScatterChart,
  Trash2,
  Waves,
  X,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { DistributionShiftResult } from '../../types.js';
import { analyzeDistributionShift } from '../../api/client.js';
import { useAuth } from '../../context/AuthContext.js';
import { Badge, Button, Card, CardHeader, Counter, EmptyState, RiskBar, cn } from '../../ui/primitives.js';
import { FindingList, LockNote, Stat } from './parts.js';
import type { PageProps } from './shared.js';

/**
 * Feature names, in vector order.
 *
 * The first five are spelled exactly as the engine's PHOTOMETRIC_FEATURES tuple spells
 * them. That is not cosmetic: the attribution step projects those axes out and re-measures
 * MMD, so a misspelling here would silently turn "explained by weather" into "unexplained
 * residual" and flip the verdict.
 */
const FEATURE_NAMES = [
  'mean_luminance',
  'contrast_std',
  'channel_red_mean',
  'channel_green_mean',
  'channel_blue_mean',
  'saturation_mean',
  'edge_density',
  'high_frequency_energy',
  'luminance_entropy',
] as const;

/** Per-side ceiling. The permutation test is O(trials x n^2); 300 keeps it under a second. */
const MAX_IMAGES_PER_SIDE = 300;
const PROBE_SIZE = 64;

interface ImageSet {
  name: string;
  vectors: number[][];
  files: string[];
  skipped: string[];
}

/**
 * Nine descriptors from the real pixels of one image.
 *
 * Everything is computed on a 64x64 probe: large enough for gradient and entropy terms to
 * be stable, small enough that three hundred files decode in a couple of seconds.
 */
async function describeImage(file: File): Promise<number[] | null> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    return null;
  }

  const canvas = document.createElement('canvas');
  canvas.width = PROBE_SIZE;
  canvas.height = PROBE_SIZE;
  const context = canvas.getContext('2d', { willReadFrequently: true });
  if (!context) {
    bitmap.close();
    return null;
  }
  context.drawImage(bitmap, 0, 0, PROBE_SIZE, PROBE_SIZE);
  bitmap.close();

  const { data } = context.getImageData(0, 0, PROBE_SIZE, PROBE_SIZE);
  const pixels = PROBE_SIZE * PROBE_SIZE;

  const luma = new Float64Array(pixels);
  let rSum = 0;
  let gSum = 0;
  let bSum = 0;
  let satSum = 0;
  const histogram = new Uint32Array(64);

  for (let i = 0; i < pixels; i += 1) {
    const r = data[i * 4] / 255;
    const g = data[i * 4 + 1] / 255;
    const b = data[i * 4 + 2] / 255;
    rSum += r;
    gSum += g;
    bSum += b;

    // Rec. 601 luma: the weighting the human eye actually applies.
    const y = 0.299 * r + 0.587 * g + 0.114 * b;
    luma[i] = y;

    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    satSum += max === 0 ? 0 : (max - min) / max;

    histogram[Math.min(63, Math.floor(y * 64))] += 1;
  }

  let lumaSum = 0;
  for (let i = 0; i < pixels; i += 1) lumaSum += luma[i];
  const meanLuma = lumaSum / pixels;

  let variance = 0;
  for (let i = 0; i < pixels; i += 1) variance += (luma[i] - meanLuma) ** 2;
  const contrastStd = Math.sqrt(variance / pixels);

  // Sobel magnitude and a 4-neighbour Laplacian, averaged over the interior.
  let gradientSum = 0;
  let laplacianSum = 0;
  let interior = 0;
  for (let y = 1; y < PROBE_SIZE - 1; y += 1) {
    for (let x = 1; x < PROBE_SIZE - 1; x += 1) {
      const at = (dx: number, dy: number) => luma[(y + dy) * PROBE_SIZE + (x + dx)];
      const gx = -at(-1, -1) - 2 * at(-1, 0) - at(-1, 1) + at(1, -1) + 2 * at(1, 0) + at(1, 1);
      const gy = -at(-1, -1) - 2 * at(0, -1) - at(1, -1) + at(-1, 1) + 2 * at(0, 1) + at(1, 1);
      gradientSum += Math.hypot(gx, gy);
      laplacianSum += Math.abs(4 * at(0, 0) - at(-1, 0) - at(1, 0) - at(0, -1) - at(0, 1));
      interior += 1;
    }
  }

  let entropy = 0;
  for (let bin = 0; bin < 64; bin += 1) {
    if (histogram[bin] === 0) continue;
    const p = histogram[bin] / pixels;
    entropy -= p * Math.log2(p);
  }

  return [
    meanLuma,
    contrastStd,
    rSum / pixels,
    gSum / pixels,
    bSum / pixels,
    satSum / pixels,
    gradientSum / interior,
    laplacianSum / interior,
    entropy,
  ];
}

const VERDICT_META: Record<string, { tone: string; ring: string; icon: React.ReactNode; headline: string }> = {
  ENVIRONMENTAL_DRIFT: {
    tone: 'text-sky-300',
    ring: 'ring-sky-500/30',
    icon: <CloudSun size={22} />,
    headline: 'Environmental drift',
  },
  SUSPICIOUS_MANIPULATION: {
    tone: 'text-rose-300',
    ring: 'ring-rose-500/30',
    icon: <Crosshair size={22} />,
    headline: 'Suspicious manipulation',
  },
  MIXED: {
    tone: 'text-amber-300',
    ring: 'ring-amber-500/30',
    icon: <Layers size={22} />,
    headline: 'Mixed signals',
  },
  INSUFFICIENT_EVIDENCE: {
    tone: 'text-slate-300',
    ring: 'ring-slate-500/30',
    icon: <AlertTriangle size={22} />,
    headline: 'Insufficient evidence',
  },
};

export const ShiftPage: React.FC<PageProps> = ({ onFindingClick, onRefresh, pushToast }) => {
  const { can } = useAuth();
  const permitted = can('analysis:run');

  const [baseline, setBaseline] = useState<ImageSet | null>(null);
  const [target, setTarget] = useState<ImageSet | null>(null);
  const [reading, setReading] = useState<'baseline' | 'target' | null>(null);
  const [progress, setProgress] = useState(0);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DistributionShiftResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const ingest = useCallback(
    async (side: 'baseline' | 'target', fileList: FileList | null) => {
      if (!fileList || fileList.length === 0) return;
      const files = Array.from(fileList)
        .filter((file) => file.type.startsWith('image/'))
        .slice(0, MAX_IMAGES_PER_SIDE);

      if (files.length === 0) {
        setError('No decodable images in that selection.');
        return;
      }

      setReading(side);
      setProgress(0);
      setError(null);

      const vectors: number[][] = [];
      const kept: string[] = [];
      const skipped: string[] = [];

      for (let index = 0; index < files.length; index += 1) {
        const vector = await describeImage(files[index]);
        if (vector) {
          vectors.push(vector);
          kept.push(files[index].name);
        } else {
          skipped.push(files[index].name);
        }
        setProgress(Math.round(((index + 1) / files.length) * 100));
      }

      const set: ImageSet = {
        name: files[0].webkitRelativePath?.split('/')[0] || `${files.length} images`,
        vectors,
        files: kept,
        skipped,
      };

      if (side === 'baseline') setBaseline(set);
      else setTarget(set);
      setReading(null);

      if (skipped.length > 0) {
        pushToast('info', `${skipped.length} file(s) could not be decoded`, 'They are excluded from the comparison.');
      }
    },
    [pushToast]
  );

  const run = async () => {
    if (!baseline || !target) return;
    setRunning(true);
    setError(null);
    try {
      const analysis = await analyzeDistributionShift({
        baselineName: baseline.name,
        targetName: target.name,
        baselineVectors: baseline.vectors,
        targetVectors: target.vectors,
        featureNames: [...FEATURE_NAMES],
      });
      setResult(analysis);
      pushToast(
        analysis.significant ? 'error' : 'ok',
        `Shift: ${analysis.status}`,
        analysis.attribution?.verdict.replace(/_/g, ' ').toLowerCase()
      );
      void onRefresh();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Analysis failed.';
      setError(message);
      pushToast('error', 'Distribution-shift analysis failed', message);
    } finally {
      setRunning(false);
    }
  };

  const ready = Boolean(baseline && target && baseline.vectors.length >= 2 && target.vectors.length >= 2);

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-2">
        <SetPicker
          side="baseline"
          title="Training baseline"
          hint="The imagery the model was validated against. This defines what normal looks like."
          set={baseline}
          busy={reading === 'baseline'}
          progress={progress}
          disabled={!permitted}
          onFiles={(files) => ingest('baseline', files)}
          onClear={() => setBaseline(null)}
        />
        <SetPicker
          side="target"
          title="Operational stream"
          hint="What the sensor is producing now. This is the batch under question."
          set={target}
          busy={reading === 'target'}
          progress={progress}
          disabled={!permitted}
          onFiles={(files) => ingest('target', files)}
          onClear={() => setTarget(null)}
        />
      </div>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-4 p-5">
          <div className="min-w-0">
            <p className="text-[13px] font-semibold">
              Maximum Mean Discrepancy · RBF kernel · median-heuristic bandwidth · permutation test
            </p>
            <p className="mt-1 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
              {ready
                ? `${baseline?.vectors.length} baseline and ${target?.vectors.length} operational descriptor vectors ready across ${FEATURE_NAMES.length} named axes.`
                : 'Load at least two decodable images on each side. Both sets are measured with the same nine descriptors so the comparison is like for like.'}
            </p>
          </div>
          <Button
            variant="primary"
            size="lg"
            onClick={run}
            loading={running}
            disabled={!ready || !permitted || reading !== null}
            icon={running ? undefined : <Waves size={16} />}
          >
            {permitted ? 'Measure shift' : 'Analysis requires an operational role'}
          </Button>
        </div>

        <div className="border-t border-[var(--color-border)] px-5 py-3.5">
          <LockNote>
            The descriptors are photometric and texture statistics measured in this browser from your
            actual files — luminance, contrast, per-channel means, saturation, edge density,
            high-frequency energy and luminance entropy. They are <strong>not</strong> backbone
            embeddings, so a semantic shift that leaves those nine statistics unchanged will not be
            detected here. Where your pipeline already exports feature vectors, post those to{' '}
            <code className="mono text-[10.5px]">/api/analyze/distribution-shift</code> instead; they
            carry far more signal.
          </LockNote>
        </div>
      </Card>

      {error && (
        <Card className="ring-1 ring-rose-500/25">
          <p className="flex items-start gap-2 p-4 text-[12px] leading-relaxed text-rose-200">
            <AlertTriangle size={15} className="mt-0.5 shrink-0" />
            {error}
          </p>
        </Card>
      )}

      <AnimatePresence mode="wait">
        {result && (
          <motion.div
            key={result.id}
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-5"
          >
            <ShiftVerdict result={result} />
            {result.featureDrifts.length > 0 && <DriftChart result={result} />}
            <FindingList findings={result.findings} onSelect={onFindingClick} title="Distribution findings" />
          </motion.div>
        )}
      </AnimatePresence>

      {!result && (
        <Card>
          <EmptyState
            icon={<ScatterChart size={20} />}
            title="No comparison run yet"
            description="MMD asks whether two sample sets could plausibly have come from the same distribution. The attribution step then asks whether any movement is diffuse (weather) or concentrated (injection)."
          />
        </Card>
      )}
    </div>
  );
};

function SetPicker({
  side,
  title,
  hint,
  set,
  busy,
  progress,
  disabled,
  onFiles,
  onClear,
}: {
  side: 'baseline' | 'target';
  title: string;
  hint: string;
  set: ImageSet | null;
  busy: boolean;
  progress: number;
  disabled: boolean;
  onFiles: (files: FileList | null) => void;
  onClear: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  return (
    <Card className={cn('transition-colors', dragging && 'border-blue-500/60')}>
      <CardHeader
        title={title}
        subtitle={hint}
        icon={side === 'baseline' ? <Images size={15} /> : <Activity size={15} />}
        action={set ? <Badge tone="accent">{set.vectors.length} vectors</Badge> : undefined}
      />
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
          onFiles(event.dataTransfer.files);
        }}
        className="px-5 pb-5"
      >
        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          multiple
          className="hidden"
          onChange={(event) => onFiles(event.target.files)}
        />

        {busy ? (
          <div className="space-y-2 py-6">
            <p className="mono text-center text-[11px] text-[var(--color-ink-muted)]">
              measuring pixels · {progress}%
            </p>
            <RiskBar value={progress} />
          </div>
        ) : set ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <p className="mono truncate text-[11.5px] text-[var(--color-ink-muted)]">{set.name}</p>
              <button
                onClick={onClear}
                className="mono flex shrink-0 items-center gap-1 text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)] transition-colors hover:text-rose-300"
              >
                <Trash2 size={11} /> clear
              </button>
            </div>
            <div className="max-h-28 overflow-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-0)]/50 p-2">
              {set.files.slice(0, 60).map((file) => (
                <p key={file} className="mono truncate text-[10px] text-[var(--color-ink-dim)]">
                  {file}
                </p>
              ))}
              {set.files.length > 60 && (
                <p className="mono text-[10px] text-[var(--color-ink-dim)]">
                  … and {set.files.length - 60} more
                </p>
              )}
            </div>
            {set.skipped.length > 0 && (
              <p className="mono flex items-center gap-1.5 text-[10px] text-amber-400">
                <X size={11} /> {set.skipped.length} file(s) could not be decoded and were excluded
              </p>
            )}
            <Button size="sm" onClick={() => inputRef.current?.click()} disabled={disabled}>
              Replace selection
            </Button>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3 py-5 text-center">
            <span className="grid h-11 w-11 place-items-center rounded-xl bg-[var(--color-surface-3)] text-[var(--color-ink-muted)] ring-1 ring-inset ring-white/5">
              <FileJson size={18} />
            </span>
            {disabled ? (
              <Badge tone="warn">Analysis requires an operational role</Badge>
            ) : (
              <>
                <Button variant="primary" size="sm" onClick={() => inputRef.current?.click()}>
                  Select images
                </Button>
                <p className="mono text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                  or drop them here · up to {MAX_IMAGES_PER_SIDE}
                </p>
              </>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}

/**
 * The verdict card leads with *whether the distribution moved*, not with the attribution.
 *
 * The attribution step always produces a verdict, including on two sets the permutation
 * test could not separate. Putting "Suspicious manipulation" in the largest type on a
 * result whose p-value is 0.26 would be the single most misleading thing this console
 * could do: it reads as an alarm for an effect that has not been established. So the
 * headline is the detection status, and when the movement is not significant the
 * attribution is demoted to a greyed, explicitly conditional line.
 */
function ShiftVerdict({ result }: { result: DistributionShiftResult }) {
  const attribution = result.attribution;
  const attributionMeta =
    VERDICT_META[attribution?.verdict ?? 'INSUFFICIENT_EVIDENCE'] ?? VERDICT_META.INSUFFICIENT_EVIDENCE;

  const moved = result.significant;
  const adversarial = attribution?.verdict === 'SUSPICIOUS_MANIPULATION';

  const meta = moved
    ? adversarial
      ? attributionMeta
      : { ...attributionMeta, headline: `Shift detected · ${attributionMeta.headline.toLowerCase()}` }
    : {
        tone: 'text-emerald-300',
        ring: 'ring-emerald-500/25',
        icon: <CloudSun size={22} />,
        headline: 'No shift established',
      };

  return (
    <Card tilt glow className={cn('ring-1', meta.ring)}>
      <div className="flex flex-wrap items-start gap-5 p-5">
        <span
          className={cn(
            'grid h-14 w-14 shrink-0 place-items-center rounded-2xl bg-[var(--color-surface-0)]/60 ring-1 ring-inset',
            meta.ring,
            meta.tone
          )}
        >
          {meta.icon}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <p className={cn('text-xl font-bold tracking-tight', meta.tone)}>{meta.headline}</p>
            <Badge tone={moved ? 'danger' : 'ok'}>
              {moved ? 'statistically significant' : 'not significant'}
            </Badge>
            <Badge tone="neutral">{result.severityBand}</Badge>
            <Badge tone="neutral">{result.status}</Badge>
          </div>

          {moved ? (
            <p className="mt-2 max-w-3xl text-[12px] leading-relaxed text-[var(--color-ink-muted)]">
              {attribution?.reasoning ?? result.limitation}
            </p>
          ) : (
            <>
              <p className="mt-2 max-w-3xl text-[12px] leading-relaxed text-[var(--color-ink-muted)]">
                The permutation test cannot separate these two sets: a difference this large arises
                by chance{' '}
                {result.pValue === null ? 'often enough to matter' : `about ${(result.pValue * 100).toFixed(0)}% of the time`}{' '}
                when both are drawn from the same distribution. Nothing here warrants action.
              </p>
              {attribution && (
                <p className="mt-2 max-w-3xl border-l-2 border-[var(--color-border-strong)] pl-3 text-[11.5px] leading-relaxed text-[var(--color-ink-dim)]">
                  <span className="mono uppercase tracking-wider">
                    attribution, had the movement been real ·{' '}
                    {attribution.verdict.replace(/_/g, ' ').toLowerCase()} ·{' '}
                  </span>
                  {attribution.reasoning}
                </p>
              )}
            </>
          )}

          <p className="mono mt-2 text-[10px] text-[var(--color-ink-dim)]">
            {result.baselineName} ({result.baselineSamples}) vs {result.targetName} ({result.targetSamples}) ·{' '}
            {result.method}
          </p>
        </div>
        <div className="w-full max-w-[220px]">
          <div className="mb-1 flex items-baseline justify-between">
            <span className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
              shift score
            </span>
            <span className="mono text-lg font-bold">
              <Counter value={result.overallShiftScore} decimals={1} />
            </span>
          </div>
          <RiskBar value={result.overallShiftScore} showBands />
        </div>
      </div>

      <div className="grid gap-4 border-t border-[var(--color-border)] px-5 py-4 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="MMD" value={result.mmd.toFixed(5)} />
        <Stat label="MMD squared" value={result.mmdSquared.toExponential(2)} />
        <Stat
          label="permutation p"
          value={result.pValue === null ? 'not computed' : result.pValue.toExponential(2)}
          tone={result.pValue !== null && result.pValue < 0.05 ? 'text-rose-400' : undefined}
        />
        <Stat
          label="displacement concentration"
          value={attribution ? attribution.displacementConcentration.toFixed(3) : '—'}
          tone={attribution && attribution.displacementConcentration > 0.6 ? 'text-rose-400' : 'text-sky-400'}
        />
        <Stat
          label="photometric explained"
          value={attribution ? `${(attribution.photometricExplainedFraction * 100).toFixed(0)}%` : '—'}
          tone={attribution && attribution.photometricExplainedFraction > 0.6 ? 'text-sky-400' : undefined}
        />
      </div>

      <div className="grid gap-4 border-t border-[var(--color-border)] px-5 py-4 sm:grid-cols-3">
        <Stat label="population stability index" value={result.populationStabilityIndex.toFixed(4)} />
        <Stat label="outlier samples" value={attribution?.outlierSampleCount ?? 0} />
        <Stat
          label="attribution confidence"
          value={attribution ? `${(attribution.confidence * 100).toFixed(0)}%` : '—'}
        />
      </div>

      <p className="border-t border-[var(--color-border)] px-5 py-3.5 text-[11px] leading-relaxed text-[var(--color-ink-dim)]">
        <span className="mono uppercase tracking-wider">limitation · </span>
        {result.limitation}
      </p>
    </Card>
  );
}

/**
 * Per-axis drift.
 *
 * Bars are coloured by the engine's own per-feature status rather than by magnitude, so a
 * large but statistically unremarkable movement does not read as an alarm.
 */
function DriftChart({ result }: { result: DistributionShiftResult }) {
  const data = useMemo(
    () =>
      result.featureDrifts.map((drift) => ({
        feature: drift.feature.replace(/_/g, ' '),
        drift: Number((drift.driftScore * 100).toFixed(2)),
        status: drift.status,
        baseline: drift.baselineMean,
        target: drift.targetMean,
      })),
    [result.featureDrifts]
  );

  return (
    <Card>
      <CardHeader
        title="Per-axis drift"
        subtitle="Relative movement of each measured descriptor, with the engine's own status per axis."
        icon={<ScatterChart size={15} />}
      />
      <div className="h-72 px-3 pb-4">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 12, left: 0, bottom: 44 }}>
            <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,0.06)" vertical={false} />
            <XAxis
              dataKey="feature"
              angle={-32}
              textAnchor="end"
              interval={0}
              tick={{ fill: 'rgba(148,163,184,0.75)', fontSize: 10 }}
              stroke="rgba(255,255,255,0.1)"
            />
            <YAxis
              tick={{ fill: 'rgba(148,163,184,0.75)', fontSize: 10 }}
              stroke="rgba(255,255,255,0.1)"
            />
            <RTooltip
              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
              contentStyle={{
                background: '#0b1220',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 12,
                fontSize: 11,
              }}
            />
            <Bar dataKey="drift" radius={[4, 4, 0, 0]} name="relative change %">
              {data.map((row) => (
                <Cell
                  key={row.feature}
                  fill={
                    row.status === 'SHIFT_DETECTED'
                      ? '#f43f5e'
                      : row.status === 'WARNING'
                        ? '#f59e0b'
                        : '#10b981'
                  }
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid gap-px border-t border-[var(--color-border)] bg-[var(--color-border)] sm:grid-cols-2 lg:grid-cols-3">
        {result.featureDrifts.map((drift) => (
          <div key={drift.feature} className="bg-[var(--color-surface-1)] px-4 py-3">
            <div className="flex items-center justify-between gap-2">
              <span className="mono truncate text-[11px]">{drift.feature.replace(/_/g, ' ')}</span>
              <Badge
                tone={drift.status === 'SHIFT_DETECTED' ? 'danger' : drift.status === 'WARNING' ? 'warn' : 'ok'}
              >
                {drift.status.replace(/_/g, ' ').toLowerCase()}
              </Badge>
            </div>
            <p className="mono mt-1 text-[10.5px] text-[var(--color-ink-dim)]">{drift.description}</p>
            {drift.pValue !== null && (
              <p className="mono mt-0.5 text-[10px] text-[var(--color-ink-dim)]">
                KS {drift.ksStatistic?.toFixed(4)} · p {drift.pValue.toExponential(2)}
              </p>
            )}
          </div>
        ))}
      </div>

      {Object.keys(result.classDistributionDrift).length > 0 && (
        <div className="border-t border-[var(--color-border)] px-5 py-4">
          <p className="mono mb-2 text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
            class balance drift
          </p>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(result.classDistributionDrift).map(([label, drift]) => (
              <div
                key={label}
                className="flex items-center justify-between gap-3 rounded-lg bg-white/[0.02] px-3 py-2"
              >
                <span className="mono truncate text-[11px]">{label}</span>
                <span className="mono text-[11px] text-[var(--color-ink-muted)]">
                  {(drift.baselineRatio * 100).toFixed(1)}% → {(drift.targetRatio * 100).toFixed(1)}%
                </span>
                <span
                  className={cn(
                    'mono text-[11px] font-semibold',
                    Math.abs(drift.delta) > 0.1 ? 'text-amber-400' : 'text-[var(--color-ink-dim)]'
                  )}
                >
                  {drift.delta >= 0 ? '+' : ''}
                  {(drift.delta * 100).toFixed(1)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}
