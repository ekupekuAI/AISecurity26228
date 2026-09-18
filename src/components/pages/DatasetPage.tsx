/**
 * Dataset integrity inspection.
 *
 * The centrepiece is the recovered trigger: when a consensus cluster is found, the engine
 * returns the actual RGB patch it reconstructed, and this page paints it. That turns
 * "12 samples are poisoned" into "here is the stamp, at these coordinates, shared by
 * these files" — which is what an analyst can act on.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { motion } from 'motion/react';
import {
  AlertTriangle,
  Copy,
  Crosshair,
  Database,
  Layers,
  ScanSearch,
  Users,
} from 'lucide-react';
import type { DatasetAnalysisResult } from '../../types.js';
import { analyzeDataset } from '../../api/client.js';
import { useAuth } from '../../context/AuthContext.js';
import {
  Badge,
  Card,
  CardHeader,
  EmptyState,
  Hash,
  RiskBar,
  cn,
} from '../../ui/primitives.js';
import { CoverageMatrix, FindingList, UploadZone } from './parts.js';
import type { PageProps } from './shared.js';

export const DatasetPage: React.FC<PageProps> = ({ onFindingClick, onRefresh, pushToast }) => {
  const { can } = useAuth();
  const [result, setResult] = useState<DatasetAnalysisResult | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = useCallback(
    async (file: File) => {
      setBusy(true);
      setResult(null);
      try {
        const analysis = await analyzeDataset(file);
        setResult(analysis);
        pushToast(
          analysis.status === 'DETECTED' ? 'error' : 'ok',
          `${analysis.status} · risk ${analysis.datasetRisk}/100`,
          `${analysis.totalSamples} samples inspected in ${analysis.analysisDurationSeconds?.toFixed(1) ?? '?'}s`
        );
        void onRefresh();
      } catch (error) {
        pushToast('error', 'Analysis failed', error instanceof Error ? error.message : undefined);
      } finally {
        setBusy(false);
      }
    },
    [onRefresh, pushToast]
  );

  return (
    <div className="space-y-5">
      <UploadZone
        disabled={!can('analysis:run')}
        busy={busy}
        accept=".zip,.tar,.gz,.tgz,.png,.jpg,.jpeg,.webp,.bmp,.tif,.tiff"
        title="Submit a dataset for inspection"
        hint="ZIP or TAR archive in COCO, YOLO or ImageFolder layout — or a single image. Archives are traversed in memory with decompression-bomb and path-traversal guards; nothing is written to disk."
        icon={<Database size={22} />}
        onFile={submit}
        deniedMessage="Your role does not hold the analysis:run capability."
      />

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
          className="space-y-5"
        >
          <SummaryCard result={result} />

          {result.triggerAnalysis && result.triggerAnalysis.clusters.length > 0 && (
            <TriggerEvidence result={result} />
          )}

          <div className="grid gap-5 lg:grid-cols-2">
            <DuplicatePanel result={result} />
            <LabelPanel result={result} />
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <ContributorPanel result={result} />
            <OodPanel result={result} />
          </div>

          <FindingList findings={result.findings} onSelect={onFindingClick} />

          {result.coverage && result.coverage.length > 0 && <CoverageMatrix entries={result.coverage} />}
        </motion.div>
      )}

      {!result && !busy && (
        <Card>
          <EmptyState
            icon={<ScanSearch size={22} />}
            title="No dataset submitted in this session"
            description="Results appear here after an archive is inspected. Previous assessments remain available under Audit & reports."
          />
        </Card>
      )}
    </div>
  );
};

/* ---------------------------------------------------------------- summary */

function SummaryCard({ result }: { result: DatasetAnalysisResult }) {
  const stats = [
    { label: 'Samples', value: result.totalSamples.toLocaleString() },
    { label: 'Decoded', value: result.decodedSamples.toLocaleString() },
    { label: 'Corrupt', value: result.corruptedFiles.toLocaleString() },
    { label: 'Classes', value: Object.keys(result.classDistribution).length.toString() },
    { label: 'Format', value: result.format },
    {
      label: 'Duration',
      value: result.analysisDurationSeconds ? `${result.analysisDurationSeconds.toFixed(1)}s` : '—',
    },
  ];

  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-4 p-5">
        <div className="min-w-0">
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <Badge
              tone={
                result.status === 'DETECTED' ? 'danger' : result.status === 'SUSPICIOUS' ? 'warn' : 'ok'
              }
            >
              {result.status}
            </Badge>
            {result.degraded && <Badge tone="warn">degraded engine</Badge>}
            {result.backbone && (
              <Badge tone={result.backbone.source === 'LOCAL_WEIGHTS' ? 'accent' : 'warn'}>
                backbone {result.backbone.source.toLowerCase().replace(/_/g, ' ')}
              </Badge>
            )}
          </div>
          <h3 className="truncate text-base font-bold">{result.filename}</h3>
          <Hash value={result.sha256} chars={40} className="mt-1" />
        </div>

        <div className="text-right">
          <p className="mono text-[9.5px] uppercase tracking-[0.16em] text-[var(--color-ink-dim)]">
            Dataset risk
          </p>
          <p
            className={cn(
              'mono text-4xl font-black leading-none',
              result.datasetRisk >= 70
                ? 'text-rose-400'
                : result.datasetRisk >= 30
                  ? 'text-amber-400'
                  : 'text-emerald-400'
            )}
          >
            {result.datasetRisk.toFixed(1)}
          </p>
          <RiskBar value={result.datasetRisk} showBands className="mt-2 w-40" />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-px border-t border-[var(--color-border)] bg-[var(--color-border)] sm:grid-cols-3 lg:grid-cols-6">
        {stats.map((stat) => (
          <div key={stat.label} className="bg-[var(--color-surface-1)] px-4 py-3">
            <p className="mono text-[9.5px] uppercase tracking-[0.14em] text-[var(--color-ink-dim)]">
              {stat.label}
            </p>
            <p className="mono mt-0.5 truncate text-[13px] font-bold">{stat.value}</p>
          </div>
        ))}
      </div>

      {result.backbone && result.backbone.source !== 'LOCAL_WEIGHTS' && (
        <div className="border-t border-amber-500/20 bg-amber-500/6 px-5 py-3">
          <p className="text-[11.5px] leading-relaxed text-amber-200/90">{result.backbone.limitation}</p>
        </div>
      )}
    </Card>
  );
}

/* --------------------------------------------------------------- triggers */

function TriggerEvidence({ result }: { result: DatasetAnalysisResult }) {
  const analysis = result.triggerAnalysis!;

  return (
    <Card glow className="ring-1 ring-rose-500/25">
      <CardHeader
        title="Backdoor trigger recovered"
        subtitle="Samples sharing an identical perturbation at identical coordinates. Natural imagery does not reproduce this; spatial consistency is the attack's functional requirement."
        icon={<Crosshair size={15} />}
        action={<Badge tone="danger">{analysis.confirmedSamples} samples</Badge>}
      />

      <div className="space-y-4 px-5 pb-5">
        {analysis.clusters.map((cluster, index) => (
          <div
            key={`${cluster.label}-${index}`}
            className="grid gap-5 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-0)]/50 p-4 md:grid-cols-[auto_1fr]"
          >
            <div className="flex flex-col items-center gap-2">
              <TriggerCanvas patch={cluster.recoveredTriggerPatch} />
              <p className="mono text-[9px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                recovered stamp
              </p>
            </div>

            <div className="min-w-0 space-y-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone="danger">target class · {cluster.label}</Badge>
                <Badge tone="neutral">{cluster.memberCount} members</Badge>
                <Badge tone="accent">p = {cluster.familyWisePValue.toExponential(1)}</Badge>
              </div>

              <p className="text-[12.5px] leading-relaxed text-[var(--color-ink-muted)]">
                {cluster.suspectedFamily}
              </p>

              <dl className="mono grid grid-cols-2 gap-x-6 gap-y-1 text-[10.5px] sm:grid-cols-4">
                <Stat label="bbox" value={`[${cluster.bbox.join(', ')}]`} />
                <Stat label="consistency" value={cluster.spatialConsistency.toFixed(2)} />
                <Stat label="magnitude" value={cluster.meanPerturbationMagnitude.toFixed(1)} />
                <Stat label="reference" value={cluster.referenceFrame} />
              </dl>

              <details className="group">
                <summary className="mono cursor-pointer text-[10.5px] text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink-muted)]">
                  affected files ({cluster.members.length} shown)
                </summary>
                <ul className="mono mt-1.5 max-h-36 space-y-0.5 overflow-y-auto text-[10.5px] text-[var(--color-ink-muted)]">
                  {cluster.members.map((member) => (
                    <li key={member} className="truncate">
                      {member}
                    </li>
                  ))}
                </ul>
              </details>
            </div>
          </div>
        ))}

        <p className="border-t border-[var(--color-border)] pt-3 text-[11px] leading-relaxed text-[var(--color-ink-dim)]">
          {analysis.limitation}
        </p>
      </div>
    </Card>
  );
}

/**
 * Paints the reconstructed trigger.
 *
 * `image-rendering: pixelated` matters here — a trigger is typically a few pixels wide,
 * and smoothing it would hide the exact structure the analyst is trying to identify.
 */
function TriggerCanvas({ patch }: { patch: number[][][] }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || !patch?.length) return;

    const height = patch.length;
    const width = patch[0]?.length ?? 0;
    if (!width) return;

    canvas.width = width;
    canvas.height = height;

    const context = canvas.getContext('2d');
    if (!context) return;

    const image = context.createImageData(width, height);
    for (let y = 0; y < height; y += 1) {
      for (let x = 0; x < width; x += 1) {
        const pixel = patch[y][x] ?? [0, 0, 0];
        const offset = (y * width + x) * 4;
        image.data[offset] = pixel[0] ?? 0;
        image.data[offset + 1] = pixel[1] ?? 0;
        image.data[offset + 2] = pixel[2] ?? 0;
        image.data[offset + 3] = 255;
      }
    }
    context.putImageData(image, 0, 0);
  }, [patch]);

  return (
    <motion.canvas
      ref={ref}
      initial={{ scale: 0.85, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 220, damping: 20 }}
      className="h-28 w-28 rounded-lg ring-1 ring-rose-500/40"
      style={{ imageRendering: 'pixelated' }}
    />
  );
}

/* -------------------------------------------------------------- sub-panels */

function DuplicatePanel({ result }: { result: DatasetAnalysisResult }) {
  const analysis = result.duplicateAnalysis;

  return (
    <Card>
      <CardHeader
        title="Duplicate flooding"
        subtitle="pHash Hamming ≤ 5, confirmed by embedding cosine > 0.98"
        icon={<Copy size={15} />}
        action={analysis ? <Badge tone={analysis.totalRedundantSamples > 0 ? 'warn' : 'ok'}>{analysis.totalRedundantSamples}</Badge> : undefined}
      />
      <div className="px-5 pb-5">
        {!analysis || analysis.totalRedundantSamples === 0 ? (
          <p className="py-3 text-[11.5px] text-[var(--color-ink-dim)]">No redundant samples detected.</p>
        ) : (
          <>
            <dl className="mono grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px]">
              <Stat label="exact duplicates" value={String(analysis.exactDuplicateSamples)} />
              <Stat label="perceptual" value={String(analysis.nearDuplicateSamples)} />
              <Stat label="clusters" value={String(analysis.clusterCount)} />
              <Stat
                label="embedding confirmed"
                value={analysis.embeddingConfirmed ? 'yes' : 'no — hash only'}
              />
            </dl>

            {result.nearDuplicateCandidates.length > 0 && (
              <div className="mt-3 max-h-44 space-y-1 overflow-y-auto border-t border-[var(--color-border)] pt-3">
                {result.nearDuplicateCandidates.slice(0, 12).map((pair, index) => (
                  <div key={index} className="mono text-[10.5px] text-[var(--color-ink-muted)]">
                    <p className="truncate">{pair.sampleA}</p>
                    <p className="truncate text-[var(--color-ink-dim)]">↔ {pair.sampleB}</p>
                    <p className="text-[9.5px] text-[var(--color-ink-dim)]">{pair.metrics}</p>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  );
}

function LabelPanel({ result }: { result: DatasetAnalysisResult }) {
  const analysis = result.labelAnalysis;

  return (
    <Card>
      <CardHeader
        title="Label consistency"
        subtitle="k-NN clean-feature cross-validation with directed class-pair flow"
        icon={<Layers size={15} />}
        action={
          analysis?.available ? (
            <Badge tone={analysis.systematicManipulation ? 'danger' : analysis.suspectCount > 0 ? 'warn' : 'ok'}>
              {analysis.suspectCount}
            </Badge>
          ) : undefined
        }
      />
      <div className="px-5 pb-5">
        {!analysis?.available ? (
          <p className="py-3 text-[11.5px] leading-relaxed text-amber-200/80">
            {analysis?.limitation ?? 'Label-consistency checking did not run.'}
          </p>
        ) : (
          <>
            <div className="mb-3 flex items-center gap-2">
              <Badge tone={analysis.systematicManipulation ? 'danger' : 'neutral'}>
                {analysis.systematicManipulation ? 'systematic flipping' : 'diffuse noise'}
              </Badge>
              <span className="mono text-[10.5px] text-[var(--color-ink-dim)]">
                {(analysis.estimatedNoiseRate * 100).toFixed(1)}% of {analysis.analysedSamples}
              </span>
            </div>

            <p className="text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
              {analysis.systematicExplanation}
            </p>

            {analysis.classPairFlows.length > 0 && (
              <div className="mt-3 space-y-1.5 border-t border-[var(--color-border)] pt-3">
                {analysis.classPairFlows.slice(0, 5).map((flow) => (
                  <div key={`${flow.fromLabel}-${flow.toLabel}`} className="flex items-center gap-2">
                    <span className="mono w-32 shrink-0 truncate text-[10.5px] text-[var(--color-ink-muted)]">
                      {flow.fromLabel} → {flow.toLabel}
                    </span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/7">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.min(100, flow.shareOfSourceClass * 400)}%` }}
                        transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
                        className="h-full rounded-full bg-amber-500"
                      />
                    </div>
                    <span className="mono w-8 shrink-0 text-right text-[10.5px]">{flow.count}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  );
}

function ContributorPanel({ result }: { result: DatasetAnalysisResult }) {
  const profiles = result.contributorProfiles ?? [];

  return (
    <Card>
      <CardHeader
        title="Contributor attribution"
        subtitle={`Strategy: ${result.contributorAttributionStrategy ?? 'unknown'}`}
        icon={<Users size={15} />}
      />
      <div className="px-5 pb-5">
        {profiles.length === 0 ? (
          <p className="py-3 text-[11.5px] text-[var(--color-ink-dim)]">
            No contributor structure found in this archive.
          </p>
        ) : (
          <div className="space-y-4">
            {profiles.map((profile) => (
              <div key={profile.name}>
                <div className="mb-1.5 flex items-baseline justify-between gap-3">
                  <span className="truncate text-[12.5px] font-semibold">{profile.name}</span>
                  <span
                    className={cn(
                      'mono shrink-0 text-[12px] font-bold',
                      profile.riskScore >= 70
                        ? 'text-rose-400'
                        : profile.riskScore >= 30
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                    )}
                  >
                    {profile.riskScore.toFixed(1)}
                  </span>
                </div>
                <RiskBar value={profile.riskScore} showBands />
                <p className="mono mt-1 text-[10px] text-[var(--color-ink-dim)]">
                  {profile.sampleCount} samples · {profile.defectDensityPercent?.toFixed(2) ?? '0'}% defect density
                </p>
                <ul className="mt-1.5 space-y-0.5">
                  {(profile.riskDrivers ?? []).slice(0, 3).map((driver) => (
                    <li key={driver} className="flex gap-1.5 text-[10.5px] leading-relaxed text-[var(--color-ink-muted)]">
                      <span className="shrink-0 text-[var(--color-ink-dim)]">·</span>
                      <span>{driver}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}

function OodPanel({ result }: { result: DatasetAnalysisResult }) {
  const analysis = result.oodAnalysis;

  return (
    <Card>
      <CardHeader
        title="Out-of-distribution samples"
        subtitle="Mahalanobis distance to class centroids, Ledoit–Wolf shrunk covariance"
        icon={<AlertTriangle size={15} />}
        action={analysis?.available ? <Badge tone={analysis.outlierCount > 0 ? 'warn' : 'ok'}>{analysis.outlierCount}</Badge> : undefined}
      />
      <div className="px-5 pb-5">
        {!analysis?.available ? (
          <p className="py-3 text-[11.5px] leading-relaxed text-amber-200/80">
            {analysis?.limitation ?? 'Out-of-distribution scoring did not run.'}
          </p>
        ) : (
          <>
            <dl className="mono grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px]">
              <Stat label="analysed" value={String(analysis.analysedSamples)} />
              <Stat label="outliers" value={String(analysis.outlierCount)} />
              <Stat label="threshold" value={analysis.thresholdDistance.toFixed(2)} />
              <Stat label="median" value={analysis.medianDistance.toFixed(2)} />
            </dl>

            {analysis.outliers.length > 0 && (
              <div className="mt-3 max-h-40 space-y-1 overflow-y-auto border-t border-[var(--color-border)] pt-3">
                {analysis.outliers.slice(0, 10).map((outlier) => (
                  <div key={outlier.path} className="mono flex items-baseline gap-2 text-[10.5px]">
                    <span className="flex-1 truncate text-[var(--color-ink-muted)]">{outlier.path}</span>
                    <span className="shrink-0 text-[var(--color-ink-dim)]">{outlier.label}</span>
                    <span className="w-12 shrink-0 text-right text-amber-400">
                      {outlier.mahalanobisDistance.toFixed(1)}
                    </span>
                  </div>
                ))}
              </div>
            )}

            <p className="mt-3 text-[10.5px] leading-relaxed text-[var(--color-ink-dim)]">{analysis.limitation}</p>
          </>
        )}
      </div>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">{label}</dt>
      <dd className="truncate text-[var(--color-ink)]">{value}</dd>
    </div>
  );
}
