import React, { useState } from 'react';
import { TrendingUp, BarChart2, Sliders, AlertTriangle, ShieldCheck, Sparkles } from 'lucide-react';
import { DistributionShiftResult, Finding } from '../../types.js';
import { analyzeDistributionShift } from '../../api/client.js';
import { StatusBadge } from '../StatusBadge.js';
import { SeverityBadge } from '../SeverityBadge.js';

interface DistributionShiftPageProps {
  onFindingClick: (finding: Finding) => void;
  onRefreshStats: () => void;
}

export const DistributionShiftPage: React.FC<DistributionShiftPageProps> = ({
  onFindingClick,
  onRefreshStats,
}) => {
  const [baselineName, setBaselineName] = useState('training_cityscapes_v1');
  const [targetName, setTargetName] = useState('production_camera_stream_delhi_subway');
  const [luminanceTarget, setLuminanceTarget] = useState(165);
  const [contrastTarget, setContrastTarget] = useState(32);
  const [redChannelTarget, setRedChannelTarget] = useState(155);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [shiftResult, setShiftResult] = useState<DistributionShiftResult | null>(null);

  const handleRunShiftAnalysis = async (customLuminance?: number, customContrast?: number) => {
    setIsAnalyzing(true);
    try {
      const lum = customLuminance !== undefined ? customLuminance : luminanceTarget;
      const cont = customContrast !== undefined ? customContrast : contrastTarget;

      const res = await analyzeDistributionShift({
        baselineName,
        targetName,
        baselineFeatures: {
          mean_luminance: 124.5,
          contrast_variance: 42.8,
          edge_density: 0.31,
          aspect_ratio: 1.33,
          channel_red_mean: 118.2,
          channel_green_mean: 122.4,
          channel_blue_mean: 130.1,
        },
        targetFeatures: {
          mean_luminance: lum,
          contrast_variance: cont,
          edge_density: 0.25,
          aspect_ratio: 1.34,
          channel_red_mean: redChannelTarget,
          channel_green_mean: 138.0,
          channel_blue_mean: 145.0,
        },
        baselineClassRatios: { road: 0.45, vehicle: 0.35, pedestrian: 0.20 },
        targetClassRatios: { road: 0.28, vehicle: 0.54, pedestrian: 0.18 },
      });
      setShiftResult(res);
      onRefreshStats();
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const applyPreset = (preset: 'WEATHER' | 'STABLE' | 'BLUR') => {
    if (preset === 'WEATHER') {
      setLuminanceTarget(185);
      setContrastTarget(26);
      setRedChannelTarget(170);
      handleRunShiftAnalysis(185, 26);
    } else if (preset === 'STABLE') {
      setLuminanceTarget(126);
      setContrastTarget(42);
      setRedChannelTarget(119);
      handleRunShiftAnalysis(126, 42);
    } else if (preset === 'BLUR') {
      setLuminanceTarget(135);
      setContrastTarget(18);
      setRedChannelTarget(130);
      handleRunShiftAnalysis(135, 18);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-zinc-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-emerald-400" />
            <h2 className="text-lg font-bold text-zinc-100">Distribution Shift &amp; Covariate Drift Surveillance</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Detects statistical divergence between baseline training datasets and live production camera streams.
          </p>
        </div>

        {/* Preset Drift Scenarios */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => applyPreset('STABLE')}
            className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
          >
            <ShieldCheck className="h-3 w-3 text-emerald-400" /> Stable Stream
          </button>
          <button
            onClick={() => applyPreset('WEATHER')}
            className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
          >
            <AlertTriangle className="h-3 w-3 text-amber-400" /> Heavy Overexposure
          </button>
          <button
            onClick={() => applyPreset('BLUR')}
            className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
          >
            <Sparkles className="h-3 w-3 text-purple-400" /> Sensor Blur Drift
          </button>
        </div>
      </div>

      {/* Control Panel */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
        <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
          <Sliders className="h-4 w-4 text-emerald-400" />
          <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
            Pipeline Stream Parameters
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div>
            <label className="text-zinc-400 block mb-1">Baseline Training Corpus Reference</label>
            <input
              type="text"
              value={baselineName}
              onChange={e => setBaselineName(e.target.value)}
              className="w-full rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-zinc-200 focus:outline-none"
            />
          </div>
          <div>
            <label className="text-zinc-400 block mb-1">Target Production Stream Identifier</label>
            <input
              type="text"
              value={targetName}
              onChange={e => setTargetName(e.target.value)}
              className="w-full rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-zinc-200 focus:outline-none"
            />
          </div>
        </div>

        {/* Feature Sliders */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-zinc-800 text-xs font-mono">
          <div>
            <div className="flex justify-between text-zinc-400 mb-1">
              <span>Target Luminance</span>
              <span className="text-zinc-200 font-bold">{luminanceTarget} (Base: 124.5)</span>
            </div>
            <input
              type="range"
              min="50"
              max="240"
              value={luminanceTarget}
              onChange={e => setLuminanceTarget(Number(e.target.value))}
              className="w-full accent-emerald-500"
            />
          </div>

          <div>
            <div className="flex justify-between text-zinc-400 mb-1">
              <span>Target Contrast Variance</span>
              <span className="text-zinc-200 font-bold">{contrastTarget} (Base: 42.8)</span>
            </div>
            <input
              type="range"
              min="10"
              max="80"
              value={contrastTarget}
              onChange={e => setContrastTarget(Number(e.target.value))}
              className="w-full accent-emerald-500"
            />
          </div>

          <div>
            <div className="flex justify-between text-zinc-400 mb-1">
              <span>Red Channel Mean</span>
              <span className="text-zinc-200 font-bold">{redChannelTarget} (Base: 118.2)</span>
            </div>
            <input
              type="range"
              min="50"
              max="240"
              value={redChannelTarget}
              onChange={e => setRedChannelTarget(Number(e.target.value))}
              className="w-full accent-emerald-500"
            />
          </div>
        </div>

        <div className="flex justify-end">
          <button
            onClick={() => handleRunShiftAnalysis()}
            disabled={isAnalyzing}
            className="rounded-lg bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-xs font-semibold text-white transition shadow disabled:opacity-50 flex items-center gap-2"
          >
            {isAnalyzing ? (
              <>
                <span className="h-3 w-3 animate-spin rounded-full border border-white border-t-transparent" />
                Evaluating Feature Drift...
              </>
            ) : (
              <>
                <TrendingUp className="h-3.5 w-3.5" /> Execute Shift Evaluation
              </>
            )}
          </button>
        </div>
      </div>

      {/* Shift Analysis Results */}
      {shiftResult && (
        <div className="space-y-6">
          {/* Status Banner */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <StatusBadge status={shiftResult.status} size="lg" />
                <span className="text-sm font-mono font-bold text-zinc-100">
                  {shiftResult.targetName} vs {shiftResult.baselineName}
                </span>
              </div>
              <p className="text-xs text-zinc-400 font-mono">
                Assessed at: {new Date(shiftResult.timestamp).toLocaleString()}
              </p>
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-right">
              <span className="text-[10px] text-zinc-400 uppercase font-mono block">Overall Covariate Shift</span>
              <span
                className={`font-mono text-2xl font-bold ${
                  shiftResult.overallShiftScore > 35
                    ? 'text-rose-400'
                    : shiftResult.overallShiftScore > 12
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {shiftResult.overallShiftScore}/100
              </span>
            </div>
          </div>

          {/* Feature Drift Table & Class Drift */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Feature Drifts */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-3">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <BarChart2 className="h-4 w-4 text-emerald-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Visual Covariate Feature Drifts
                </h3>
              </div>

              <div className="space-y-2.5">
                {shiftResult.featureDrifts.map(f => (
                  <div key={f.feature} className="rounded-lg border border-zinc-800 bg-zinc-950 p-2.5 text-xs font-mono space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="text-zinc-200 font-bold">{f.feature}</span>
                      <StatusBadge status={f.status} size="sm" />
                    </div>
                    <p className="text-[11px] text-zinc-400 font-sans">{f.description}</p>
                    <div className="flex justify-between items-center text-[10px] text-zinc-500 pt-1">
                      <span>Drift Coefficient:</span>
                      <span className="font-bold text-zinc-300">{(f.driftScore * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Class Distribution Drift */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-3">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <BarChart2 className="h-4 w-4 text-purple-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Class Proportion Divergence
                </h3>
              </div>

              <div className="divide-y divide-zinc-800 text-xs font-mono">
                {Object.entries(shiftResult.classDistributionDrift).map(([cls, rawInfo]) => {
                  const info = rawInfo as { baselineRatio: number; targetRatio: number; delta: number };
                  return (
                    <div key={cls} className="py-2.5 flex items-center justify-between">
                      <div>
                        <span className="text-zinc-200 font-bold capitalize">{cls}</span>
                        <span className="text-[11px] text-zinc-500 block">
                          Base: {(info.baselineRatio * 100).toFixed(0)}% | Target: {(info.targetRatio * 100).toFixed(0)}%
                        </span>
                      </div>
                      <span
                        className={`font-bold ${
                          info.delta > 0.1 ? 'text-amber-400' : info.delta < -0.1 ? 'text-rose-400' : 'text-zinc-400'
                        }`}
                      >
                        {info.delta > 0 ? `+${(info.delta * 100).toFixed(1)}%` : `${(info.delta * 100).toFixed(1)}%`}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Findings */}
          {shiftResult.findings && shiftResult.findings.length > 0 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-3">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Drift Findings ({shiftResult.findings.length})
                </h3>
              </div>

              <div className="divide-y divide-zinc-800">
                {shiftResult.findings.map(f => (
                  <div
                    key={f.id}
                    onClick={() => onFindingClick(f)}
                    className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-zinc-800/30 px-2 rounded cursor-pointer transition"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.severity} size="sm" />
                        <span className="font-mono text-xs font-bold text-zinc-200">{f.findingId}</span>
                      </div>
                      <p className="text-xs text-zinc-300">{f.explanation}</p>
                    </div>
                    <span className="text-xs text-emerald-400 font-mono hover:underline">
                      Inspect Evidence &rarr;
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
