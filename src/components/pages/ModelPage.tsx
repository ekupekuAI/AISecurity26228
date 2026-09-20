/**
 * Model integrity inspection.
 *
 * The access mode is shown before any verdict, because a clean result under BLACK_BOX
 * and a clean result under WHITE_BOX mean completely different things. Neural Cleanse
 * results are rendered as the per-class L1 comparison the method actually rests on, with
 * the recovered mask painted alongside.
 */

import React from 'react';
import { motion } from 'motion/react';
import {
  Activity,
  Binary,
  Boxes,
  Crosshair,
  Eye,
  EyeOff,
  Gauge,
  ShieldAlert,
  Siren,
} from 'lucide-react';
import type { AnalysisMode, ModelAnalysisResult } from '../../types.js';
import { useAuth } from '../../context/AuthContext.js';
import { useWorkbench } from '../../context/WorkbenchContext.js';
import { Badge, Card, CardHeader, EmptyState, Hash, RiskBar, cn } from '../../ui/primitives.js';
import { AssetDecisionPanel, DegradedBanner } from '../AssetDecisionPanel.js';
import { CoverageMatrix, FindingList, IssuePassport, LockNote, Stat, UploadZone } from './parts.js';
import type { PageProps } from './shared.js';

const MODE_META: Record<AnalysisMode, { tone: 'ok' | 'warn' | 'danger' | 'neutral'; icon: React.ReactNode; blurb: string }> = {
  WHITE_BOX: {
    tone: 'ok',
    icon: <Eye size={13} />,
    blurb: 'Parameters loaded into a matching architecture and executed. Behavioural claims are meaningful.',
  },
  GREY_BOX: {
    tone: 'warn',
    icon: <EyeOff size={13} />,
    blurb: 'Structure parsed but the model was not executed. No behavioural conclusion is available.',
  },
  BLACK_BOX: {
    tone: 'warn',
    icon: <EyeOff size={13} />,
    blurb: 'Only the container and digest were inspected. Absence of a finding is not evidence of absence.',
  },
  REFUSED: {
    tone: 'danger',
    icon: <ShieldAlert size={13} />,
    blurb: 'Inspection stopped on safety grounds. The checkpoint was never deserialised.',
  },
};

export const ModelPage: React.FC<PageProps> = ({ onFindingClick, pushToast }) => {
  const { can } = useAuth();
  const { model, runModel } = useWorkbench();
  const { result, busy, fileName, error } = model;

  return (
    <div className="space-y-5">
      <UploadZone
        disabled={!can('analysis:run')}
        busy={busy}
        lastFileName={fileName}
        accept=".pt,.pth,.onnx,.ts,.torchscript,.safetensors,.bin"
        title="Submit a model checkpoint"
        hint="PyTorch, TorchScript, ONNX or safetensors. The opcode audit runs before anything is deserialised."
        icon={<Boxes size={22} />}
        onFile={runModel}
        deniedMessage="Your role does not hold the analysis:run capability."
      />

      {error && !busy && !result && (
        <Card className="ring-1 ring-rose-500/30">
          <div className="flex items-start gap-3 p-5">
            <span className="mt-0.5 shrink-0 text-rose-400">
              <ShieldAlert size={20} />
            </span>
            <div className="min-w-0">
              <p className="text-[13px] font-bold text-rose-300">Model analysis failed</p>
              <p className="mt-1 text-[12px] leading-relaxed text-[var(--color-ink-muted)]">{error}</p>
              <p className="mt-1 text-[11px] leading-relaxed text-[var(--color-ink-dim)]">
                The checkpoint was not assessed — this is not a clean result. Check that the assurance engine
                is running, then submit again.
              </p>
            </div>
          </div>
        </Card>
      )}

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
          className="space-y-5"
        >
          {(result.degraded || result.engine === 'node-fallback') && (
            <DegradedBanner reason={result.degradedReason} />
          )}

          <SummaryCard result={result} />

          {result.governance && <AssetDecisionPanel decision={result.governance} />}

          <div className="flex justify-end">
            <IssuePassport analysisId={result.id} pushToast={pushToast} />
          </div>

          {result.pickleAudit && <SerializationPanel result={result} />}

          {result.neuralCleanse?.ran && <NeuralCleansePanel result={result} />}

          {result.behaviouralBattery?.ran && <BatteryPanel result={result} />}

          {result.weightStatistics && <WeightPanel result={result} />}

          <FindingList findings={result.findings} onSelect={onFindingClick} />

          <Card>
            <CardHeader title="Assessment limitations" icon={<Siren size={15} />} />
            <div className="px-5 pb-5">
              <p className="text-[12px] leading-relaxed text-amber-200/85">{result.limitations}</p>
            </div>
          </Card>

          {result.coverage && result.coverage.length > 0 && <CoverageMatrix entries={result.coverage} />}
        </motion.div>
      )}

      {!result && !busy && !error && (
        <Card>
          <EmptyState
            icon={<Boxes size={22} />}
            title="No checkpoint submitted in this session"
            description="Results appear here after a model is inspected. Previous assessments remain available under Audit & reports."
          />
        </Card>
      )}
    </div>
  );
};

function SummaryCard({ result }: { result: ModelAnalysisResult }) {
  const mode = MODE_META[result.analysisMode] ?? MODE_META.BLACK_BOX;

  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-4 p-5">
        <div className="min-w-0">
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <Badge tone={result.status === 'DETECTED' ? 'danger' : result.status === 'SUSPICIOUS' ? 'warn' : 'ok'}>
              {result.status}
            </Badge>
            <Badge tone={mode.tone}>
              {mode.icon}
              {result.analysisMode.replace(/_/g, '-').toLowerCase()}
            </Badge>
            {result.degraded && <Badge tone="warn">degraded engine</Badge>}
          </div>
          <h3 className="truncate text-base font-bold">{result.filename}</h3>
          <Hash value={result.sha256} chars={40} className="mt-1" />
          <p className="mt-2 max-w-xl text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">{mode.blurb}</p>
        </div>

        <div className="text-right">
          <p className="mono text-[9.5px] uppercase tracking-[0.16em] text-[var(--color-ink-dim)]">Model risk</p>
          <p
            className={cn(
              'mono text-4xl font-black leading-none',
              result.modelRisk >= 70 ? 'text-rose-400' : result.modelRisk >= 30 ? 'text-amber-400' : 'text-emerald-400'
            )}
          >
            {result.modelRisk.toFixed(1)}
          </p>
          <RiskBar value={result.modelRisk} showBands className="mt-2 w-40" />
          {result.backdoorConfidence > 0 && (
            <p className="mono mt-2 text-[10.5px] text-rose-300">
              backdoor confidence {(result.backdoorConfidence * 100).toFixed(0)}%
            </p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-px border-t border-[var(--color-border)] bg-[var(--color-border)] sm:grid-cols-4">
        <Cell label="Framework" value={result.framework} />
        <Cell label="Architecture" value={result.architecture} />
        <Cell label="Parameters" value={result.parameterCount ? result.parameterCount.toLocaleString() : '—'} />
        <Cell
          label="Duration"
          value={result.analysisDurationSeconds ? `${result.analysisDurationSeconds.toFixed(1)}s` : '—'}
        />
      </div>
    </Card>
  );
}

function Cell({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[var(--color-surface-1)] px-4 py-3">
      <p className="mono text-[9.5px] uppercase tracking-[0.14em] text-[var(--color-ink-dim)]">{label}</p>
      <p className="mono mt-0.5 truncate text-[12px] font-semibold" title={value}>
        {value}
      </p>
    </div>
  );
}

function SerializationPanel({ result }: { result: ModelAnalysisResult }) {
  const audit = result.pickleAudit!;
  const hostile = audit.verdict === 'MALICIOUS';

  return (
    <Card className={cn(hostile && 'ring-1 ring-rose-500/30')} glow={hostile}>
      <CardHeader
        title="Serialisation audit"
        subtitle="Full opcode disassembly against a symbol allowlist. A stream that cannot be parsed is treated as hostile."
        icon={<Binary size={15} />}
        action={
          <Badge tone={hostile ? 'danger' : audit.verdict === 'SUSPICIOUS' ? 'warn' : 'ok'}>{audit.verdict}</Badge>
        }
      />
      <div className="space-y-4 px-5 pb-5">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2.5 sm:grid-cols-4">
          <Stat label="container" value={audit.container} />
          <Stat label="streams" value={String(audit.streamsScanned)} />
          <Stat label="opcodes" value={audit.opcodeCount.toLocaleString()} />
          <Stat
            label="safe to load"
            value={audit.safeToLoad ? 'yes' : 'no'}
            tone={audit.safeToLoad ? 'text-emerald-400' : 'text-rose-400'}
          />
        </dl>

        {audit.criticalGlobals.length > 0 && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/8 p-3.5">
            <p className="mono mb-2 text-[10px] uppercase tracking-wider text-rose-300">
              Execution primitives found
            </p>
            <ul className="space-y-1">
              {audit.criticalGlobals.map((entry, index) => (
                <li key={index} className="mono flex items-baseline gap-2 text-[11.5px] text-rose-200">
                  <span className="text-rose-400">✗</span>
                  <span className="font-bold">{entry.qualname}</span>
                  <span className="text-[10px] text-rose-300/60">at byte {entry.offset}</span>
                </li>
              ))}
            </ul>
            <p className="mt-2.5 text-[11px] leading-relaxed text-rose-200/80">
              Calling <code className="mono">torch.load</code> on this file would execute this code before
              a single tensor was read.
            </p>
          </div>
        )}

        {audit.truncatedStreams.length > 0 && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/8 p-3.5">
            <p className="mono mb-2 text-[10px] uppercase tracking-wider text-rose-300">Broken stream</p>
            {audit.truncatedStreams.map((stream, index) => (
              <p key={index} className="mono text-[11px] leading-relaxed text-rose-200/85">
                {stream.stream}: {stream.opcodesDecodedBeforeFailure} opcodes decoded before failure,{' '}
                {stream.bytesUnparsed} bytes unparsed — {stream.error}
              </p>
            ))}
            <p className="mt-2 text-[11px] leading-relaxed text-rose-200/80">
              Opcodes preceding the failure would already have executed. This is the published nullifAI
              evasion pattern; a scanner that treats a parse error as "nothing found" passes this file.
            </p>
          </div>
        )}

        {audit.notes.length > 0 && (
          <ul className="space-y-1">
            {audit.notes.map((note, index) => (
              <li key={index} className="text-[11px] leading-relaxed text-[var(--color-ink-muted)]">
                · {note}
              </li>
            ))}
          </ul>
        )}

        {audit.globalsFound.length > 0 && (
          <details>
            <summary className="mono cursor-pointer text-[10.5px] text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink-muted)]">
              enumerated symbols ({audit.globalsFound.length})
            </summary>
            <div className="mono mt-2 max-h-40 space-y-0.5 overflow-y-auto text-[10.5px] text-[var(--color-ink-muted)]">
              {audit.globalsFound.map((entry, index) => (
                <p key={index} className="truncate">
                  {entry.qualname}
                </p>
              ))}
            </div>
          </details>
        )}
      </div>
    </Card>
  );
}

/**
 * Neural Cleanse.
 *
 * The bar chart is the method: a backdoored class needs a dramatically smaller universal
 * perturbation than every other class. Showing per-class L1 relative to the median makes
 * the asymmetry visible rather than asking the reader to trust a single index.
 */
function NeuralCleansePanel({ result }: { result: ModelAnalysisResult }) {
  const report = result.neuralCleanse!;
  const maxL1 = Math.max(...report.inversions.map((inversion) => inversion.l1Norm), 1);

  return (
    <Card className={cn(report.flaggedClasses.length > 0 && 'ring-1 ring-rose-500/25')}>
      <CardHeader
        title="Neural Cleanse trigger inversion"
        subtitle="Minimal universal perturbation recovered per class. A class reachable by a far smaller mask than every other is the signature of an implanted shortcut."
        icon={<Crosshair size={15} />}
        action={
          <Badge tone={report.flaggedClasses.length > 0 ? 'danger' : 'ok'}>
            {report.flaggedClasses.length > 0 ? `class ${report.flaggedClasses.join(', ')}` : 'no shortcut'}
          </Badge>
        }
      />

      <div className="space-y-4 px-5 pb-5">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2.5 sm:grid-cols-4">
          <Stat label="classes scanned" value={`${report.classesScanned}/${report.classesTotal}`} />
          <Stat label="median L1" value={report.medianL1.toFixed(1)} />
          <Stat
            label="max anomaly index"
            value={`${report.maxAnomalyIndex.toFixed(2)} / ${report.anomalyIndexThreshold}`}
          />
          <Stat label="duration" value={`${report.durationSeconds.toFixed(0)}s`} />
        </dl>

        <div className="space-y-1.5">
          {report.inversions.map((inversion) => {
            const width = (inversion.l1Norm / maxL1) * 100;
            return (
              <div key={inversion.classIndex} className="flex items-center gap-3">
                <span
                  className={cn(
                    'mono w-16 shrink-0 text-[10.5px]',
                    inversion.flagged ? 'font-bold text-rose-300' : 'text-[var(--color-ink-dim)]'
                  )}
                >
                  class {inversion.classIndex}
                </span>
                <div className="relative h-4 flex-1 overflow-hidden rounded bg-white/5">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${width}%` }}
                    transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1], delay: inversion.classIndex * 0.03 }}
                    className={cn('h-full rounded', inversion.flagged ? 'bg-rose-500' : 'bg-[var(--color-border-strong)]')}
                  />
                  {/* The median line is what every bar is judged against. */}
                  <span
                    className="absolute inset-y-0 w-px bg-blue-400/70"
                    style={{ left: `${(report.medianL1 / maxL1) * 100}%` }}
                    title="across-class median"
                  />
                </div>
                <span
                  className={cn(
                    'mono w-28 shrink-0 text-right text-[10.5px]',
                    inversion.flagged ? 'text-rose-300' : 'text-[var(--color-ink-muted)]'
                  )}
                >
                  {inversion.l1Norm.toFixed(1)} · {(inversion.l1RatioToMedian * 100).toFixed(0)}%
                </span>
                {inversion.flagged && <ShieldAlert size={13} className="shrink-0 text-rose-400" />}
              </div>
            );
          })}
        </div>

        <p className="mono text-[10px] text-[var(--color-ink-dim)]">
          blue line = across-class median · flag requires L1 ≤{' '}
          {((report.l1RatioThreshold ?? 0.55) * 100).toFixed(0)}% of median with anomaly index &gt;{' '}
          {report.anomalyIndexThreshold}, or a decisively smaller mask on its own
        </p>

        <LockNote>{report.limitation}</LockNote>
      </div>
    </Card>
  );
}

function BatteryPanel({ result }: { result: ModelAnalysisResult }) {
  const report = result.behaviouralBattery!;

  if (report.degenerateBaseline) {
    return (
      <Card>
        <CardHeader title="Behavioural battery" icon={<Activity size={15} />} action={<Badge tone="warn">not scored</Badge>} />
        <div className="px-5 pb-5">
          <p className="text-[12px] leading-relaxed text-amber-200/85">{report.limitation}</p>
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader
        title="Behavioural trigger battery"
        subtitle="A backdoor drives inputs to one specific class from every source class. Concentration and lift over the clean baseline are the discriminators, not flip rate alone."
        icon={<Activity size={15} />}
        action={
          <Badge tone={report.backdoorConfidence > 0 ? 'danger' : 'ok'}>
            {report.backdoorConfidence > 0
              ? `target class ${report.suspectedTargetClass}`
              : 'no directed response'}
          </Badge>
        }
      />
      <div className="space-y-3 px-5 pb-5">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2.5 sm:grid-cols-4">
          <Stat label="input shape" value={report.inputShape.join(' × ')} />
          <Stat label="classes" value={String(report.classCount)} />
          <Stat label="baseline entropy" value={`${report.cleanPredictionEntropy.toFixed(2)} bits`} />
          <Stat
            label="backdoor confidence"
            value={`${(report.backdoorConfidence * 100).toFixed(0)}%`}
            tone={report.backdoorConfidence > 0 ? 'text-rose-400' : undefined}
          />
        </dl>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[620px]">
            <thead>
              <tr className="mono text-[9.5px] uppercase tracking-wider text-[var(--color-ink-dim)]">
                <th className="py-2 text-left font-medium">Battery</th>
                <th className="py-2 text-right font-medium">Flip</th>
                <th className="py-2 text-right font-medium">Concentration</th>
                <th className="py-2 text-right font-medium">Lift</th>
                <th className="py-2 text-right font-medium">Target</th>
                <th className="py-2 text-right font-medium">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {report.batteries.map((battery) => {
                const strong = battery.verdict === 'STRONG_BACKDOOR_INDICATION';
                return (
                  <tr key={battery.name} className="border-t border-[var(--color-border)]">
                    <td className="py-2">
                      <p className={cn('mono text-[11px]', strong && 'font-bold text-rose-300')}>{battery.name}</p>
                      <p className="text-[10px] text-[var(--color-ink-dim)]">{battery.description}</p>
                    </td>
                    <td className="mono py-2 text-right text-[11px]">{(battery.flipRate * 100).toFixed(0)}%</td>
                    <td className="mono py-2 text-right text-[11px]">
                      {(battery.flipConcentration * 100).toFixed(0)}%
                    </td>
                    <td className="mono py-2 text-right text-[11px]">{battery.liftOverBaseline.toFixed(1)}×</td>
                    <td className="mono py-2 text-right text-[11px]">{battery.targetClass ?? '—'}</td>
                    <td className="py-2 text-right">
                      <Badge
                        tone={
                          strong ? 'danger' : battery.verdict === 'SUSPICIOUS' ? 'warn' : 'neutral'
                        }
                      >
                        {battery.verdict.replace(/_/g, ' ').toLowerCase()}
                      </Badge>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <LockNote>{report.limitation}</LockNote>
      </div>
    </Card>
  );
}

function WeightPanel({ result }: { result: ModelAnalysisResult }) {
  const stats = result.weightStatistics!;

  return (
    <Card>
      <CardHeader
        title="Parameter statistics"
        subtitle="Separates typical from anomalous. Unusual statistics warrant review; they are not proof of malice."
        icon={<Gauge size={15} />}
        action={
          <Badge tone={stats.anomalyScore > 0.3 ? 'warn' : 'ok'}>
            anomaly {(stats.anomalyScore * 100).toFixed(0)}%
          </Badge>
        }
      />
      <div className="space-y-3 px-5 pb-5">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2.5 sm:grid-cols-4">
          <Stat label="tensors" value={String(stats.tensorCount)} />
          <Stat label="parameters" value={stats.totalParameters.toLocaleString()} />
          <Stat
            label="non-finite"
            value={String(stats.nanTensors.length + stats.infTensors.length)}
            tone={stats.nanTensors.length + stats.infTensors.length > 0 ? 'text-rose-400' : undefined}
          />
          <Stat
            label="dead tensors"
            value={String(stats.deadTensors.length)}
            tone={stats.deadTensors.length > 0 ? 'text-amber-400' : undefined}
          />
        </dl>

        {stats.outlierNeuronTensors.length > 0 && (
          <div className="rounded-lg border border-amber-500/25 bg-amber-500/6 p-3">
            <p className="mono mb-1.5 text-[10px] uppercase tracking-wider text-amber-300">
              Outlier output channels
            </p>
            {stats.outlierNeuronTensors.slice(0, 5).map((tensor) => (
              <p key={tensor.name} className="mono text-[10.5px] text-amber-200/85">
                {tensor.name} — {(tensor.outlierRowFraction * 100).toFixed(2)}% of channels
              </p>
            ))}
            <p className="mt-1.5 text-[10.5px] leading-relaxed text-amber-200/70">
              Backdoor implantation by direct weight editing concentrates its change in a few neurons.
              Correlate with the trigger-inversion result before drawing a conclusion.
            </p>
          </div>
        )}

        <details>
          <summary className="mono cursor-pointer text-[10.5px] text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink-muted)]">
            largest tensors
          </summary>
          <div className="mono mt-2 max-h-44 space-y-0.5 overflow-y-auto text-[10.5px]">
            {stats.largestTensors.map((tensor) => (
              <div key={tensor.name} className="flex items-baseline gap-3">
                <span className="flex-1 truncate text-[var(--color-ink-muted)]">{tensor.name}</span>
                <span className="shrink-0 text-[var(--color-ink-dim)]">[{tensor.shape.join('×')}]</span>
                <span className="w-24 shrink-0 text-right text-[var(--color-ink-dim)]">
                  μ {tensor.mean.toFixed(3)} σ {tensor.std.toFixed(3)}
                </span>
              </div>
            ))}
          </div>
        </details>
      </div>
    </Card>
  );
}
