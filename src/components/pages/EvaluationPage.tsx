import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ReferenceLine,
  ComposedChart,
} from 'recharts';
import {
  Activity,
  Cpu,
  TrendingUp,
  PieChart as PieIcon,
  BarChart2,
  ShieldCheck,
  Zap,
  Target,
  RefreshCw,
  Sliders,
  Sparkles,
} from 'lucide-react';
import { PROJECT_MODELS, ModelPredictionDataset } from '../../data/projectPredictionData.js';

export const EvaluationPage: React.FC = () => {
  const [selectedModelKey, setSelectedModelKey] = useState<string>('defense-yolov8-ir');
  const [sampleLimit, setSampleLimit] = useState<number>(30);
  const [activeConfidenceFilter, setActiveConfidenceFilter] = useState<'ALL' | 'VERIFIED' | 'TAMPERED'>('ALL');
  const [hoveredPrediction, setHoveredPrediction] = useState<string | null>(null);

  const currentDataset: ModelPredictionDataset = useMemo(() => {
    return PROJECT_MODELS[selectedModelKey] || PROJECT_MODELS['defense-yolov8-ir'];
  }, [selectedModelKey]);

  // Filter predictions based on sampleLimit and filter
  const filteredPredictions = useMemo(() => {
    let list = currentDataset.predictions.slice(0, sampleLimit);
    if (activeConfidenceFilter === 'VERIFIED') {
      list = list.filter((p) => p.status === 'VERIFIED');
    } else if (activeConfidenceFilter === 'TAMPERED') {
      list = list.filter((p) => p.status === 'TAMPERED');
    }
    return list;
  }, [currentDataset, sampleLimit, activeConfidenceFilter]);

  // Radar metrics data
  const radarData = useMemo(() => {
    return [
      {
        metric: 'Precision %',
        ...currentDataset.classes.reduce(
          (acc, c) => ({ ...acc, [c.className]: c.precision }),
          {}
        ),
      },
      {
        metric: 'Recall %',
        ...currentDataset.classes.reduce(
          (acc, c) => ({ ...acc, [c.className]: c.recall }),
          {}
        ),
      },
      {
        metric: 'F1 Score %',
        ...currentDataset.classes.reduce(
          (acc, c) => ({ ...acc, [c.className]: c.f1Score }),
          {}
        ),
      },
      {
        metric: 'Confidence %',
        ...currentDataset.classes.reduce(
          (acc, c) => ({ ...acc, [c.className]: c.avgConfidence }),
          {}
        ),
      },
      {
        metric: 'Accuracy %',
        ...currentDataset.classes.reduce(
          (acc, c) => ({ ...acc, [c.className]: c.recall + (100 - c.recall) * 0.4 }),
          {}
        ),
      },
    ];
  }, [currentDataset]);

  return (
    <div id="ml-prediction-graphs-page" className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1600px] mx-auto text-zinc-100">
      {/* MODEL SELECTOR & CONTROLS BAR */}
      <div
        id="prediction-controls-bar"
        className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-4 sm:p-5 shadow-xl backdrop-blur flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center gap-3">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm tracking-wider uppercase">
            <Cpu className="w-5 h-5 text-emerald-400" />
            <span>Target ML Model:</span>
          </div>
          <div className="inline-flex rounded-lg bg-zinc-950 p-1 border border-zinc-800">
            {Object.keys(PROJECT_MODELS).map((key) => {
              const m = PROJECT_MODELS[key];
              const isSelected = selectedModelKey === key;
              return (
                <button
                  key={key}
                  id={`model-select-${key}`}
                  onClick={() => setSelectedModelKey(key)}
                  className={`px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md transition-all ${
                    isSelected
                      ? 'bg-emerald-600 text-white shadow-md'
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
                  }`}
                >
                  {key === 'defense-yolov8-ir' && 'YOLOv8-IR Surveillance'}
                  {key === 'traffic-resnet18' && 'PreAct-ResNet18 Recon'}
                  {key === 'uav-mobilenet-v3' && 'UAV MobileNet-V3 Target'}
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Sample Size Toggle */}
          <div className="flex items-center gap-1.5 bg-zinc-950 px-3 py-1.5 rounded-lg border border-zinc-800 text-xs text-zinc-400">
            <Sliders className="w-3.5 h-3.5 text-zinc-400" />
            <span className="font-medium text-zinc-300">Horizon:</span>
            {[15, 30].map((count) => (
              <button
                key={count}
                id={`horizon-btn-${count}`}
                onClick={() => setSampleLimit(count)}
                className={`px-2 py-0.5 rounded text-xs transition-colors ${
                  sampleLimit === count
                    ? 'bg-zinc-700 text-white font-bold'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {count}
              </button>
            ))}
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs">
            {(['ALL', 'VERIFIED', 'TAMPERED'] as const).map((filter) => (
              <button
                key={filter}
                id={`filter-btn-${filter.toLowerCase()}`}
                onClick={() => setActiveConfidenceFilter(filter)}
                className={`px-2.5 py-1 rounded transition-colors font-medium ${
                  activeConfidenceFilter === filter
                    ? filter === 'TAMPERED'
                      ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {filter === 'ALL' && 'All Inferences'}
                {filter === 'VERIFIED' && 'Verified Only'}
                {filter === 'TAMPERED' && 'Anomalous / Shifted'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* METRIC GAUGES & VISUAL SUMMARY CARDS */}
      <div id="prediction-metric-gauges" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Overall Accuracy */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-semibold text-zinc-400 uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <Target className="w-4 h-4 text-emerald-400" />
              Model Accuracy %
            </span>
            <span className="text-emerald-400 font-mono">Target: ≥90%</span>
          </div>
          <div className="my-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono">
              {currentDataset.overallAccuracyPct.toFixed(1)}%
            </span>
            <span className="text-xs text-emerald-400 font-medium">Optimal</span>
          </div>
          <div className="w-full bg-zinc-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-emerald-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${currentDataset.overallAccuracyPct}%` }}
            />
          </div>
        </div>

        {/* Metric 2: Mean Confidence */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-semibold text-zinc-400 uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <TrendingUp className="w-4 h-4 text-blue-400" />
              Mean Confidence %
            </span>
            <span className="text-blue-400 font-mono">Softmax Mean</span>
          </div>
          <div className="my-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono">
              {currentDataset.meanConfidencePct.toFixed(1)}%
            </span>
            <span className="text-xs text-blue-400 font-medium">Calibrated</span>
          </div>
          <div className="w-full bg-zinc-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${currentDataset.meanConfidencePct}%` }}
            />
          </div>
        </div>

        {/* Metric 3: Verification Provenance Rate */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-semibold text-zinc-400 uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-purple-400" />
              Cryptographic Integrity %
            </span>
            <span className="text-purple-400 font-mono">SHA-256 Provenance</span>
          </div>
          <div className="my-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono">
              {currentDataset.verificationRatePct.toFixed(1)}%
            </span>
            <span className="text-xs text-purple-400 font-medium">Signed</span>
          </div>
          <div className="w-full bg-zinc-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-purple-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${currentDataset.verificationRatePct}%` }}
            />
          </div>
        </div>

        {/* Metric 4: Mean Inference Compute Latency */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-semibold text-zinc-400 uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <Zap className="w-4 h-4 text-amber-400" />
              Mean Inference Latency
            </span>
            <span className="text-amber-400 font-mono">Edge Compute</span>
          </div>
          <div className="my-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono">
              {currentDataset.avgLatencyMs.toFixed(1)} ms
            </span>
            <span className="text-xs text-amber-400 font-medium">Real-Time</span>
          </div>
          <div className="w-full bg-zinc-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-amber-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${Math.min(100, (currentDataset.avgLatencyMs / 40) * 100)}%` }}
            />
          </div>
        </div>
      </div>

      {/* PRIMARY CHART 1: SEQUENTIAL PREDICTION CONFIDENCE TRAJECTORY (%) STREAM */}
      <div
        id="chart-prediction-stream"
        className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-xl"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-emerald-400" />
              Prediction Confidence Percentage Stream (Inference Time-Series)
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Outputs for {currentDataset.modelName} — Sequential prediction confidence % and classification matches
            </p>
          </div>
          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full bg-emerald-500 inline-block" />
              <span className="text-zinc-300">Confidence % (≥90% Optimal)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full bg-red-500 inline-block" />
              <span className="text-zinc-300">Target Mismatch / Shift</span>
            </div>
          </div>
        </div>

        <div className="h-72 sm:h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={filteredPredictions}
              margin={{ top: 10, right: 15, left: -10, bottom: 0 }}
            >
              <defs>
                <linearGradient id="predictionConfidenceGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
              <XAxis
                dataKey="sampleIndex"
                stroke="#71717a"
                tick={{ fontSize: 11, fill: '#71717a' }}
                tickFormatter={(val) => `#${val}`}
              />
              <YAxis
                domain={[70, 100]}
                stroke="#71717a"
                tick={{ fontSize: 11, fill: '#71717a' }}
                tickFormatter={(val) => `${val}%`}
              />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload as (typeof filteredPredictions)[0];
                    return (
                      <div className="bg-zinc-950 border border-zinc-700 rounded-lg p-3 shadow-2xl text-xs space-y-1.5">
                        <div className="font-mono text-zinc-300 font-bold border-b border-zinc-800 pb-1 flex justify-between gap-4">
                          <span>Sample #{data.sampleIndex}</span>
                          <span
                            className={
                              data.isCorrect ? 'text-emerald-400' : 'text-red-400 font-semibold'
                            }
                          >
                            {data.isCorrect ? 'MATCH' : 'MISMATCH'}
                          </span>
                        </div>
                        <div className="text-zinc-400">
                          Target Class:{' '}
                          <span className="text-white font-mono">{data.targetClass}</span>
                        </div>
                        <div className="text-zinc-400">
                          Predicted Output:{' '}
                          <span
                            className={
                              data.isCorrect
                                ? 'text-emerald-400 font-mono font-bold'
                                : 'text-amber-400 font-mono font-bold'
                            }
                          >
                            {data.predictedClass}
                          </span>
                        </div>
                        <div className="text-zinc-400">
                          Confidence Score:{' '}
                          <span className="text-emerald-400 font-mono font-bold">
                            {data.confidencePct.toFixed(1)}%
                          </span>
                        </div>
                        <div className="text-zinc-400">
                          Compute Latency:{' '}
                          <span className="text-zinc-200 font-mono">{data.latencyMs} ms</span>
                        </div>
                        <div className="text-zinc-400">
                          Asset File:{' '}
                          <span className="text-zinc-400 font-mono text-[10px]">
                            {data.sampleName}
                          </span>
                        </div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <ReferenceLine
                y={90}
                stroke="#f59e0b"
                strokeDasharray="4 4"
                label={{
                  value: '90% Quality Baseline',
                  fill: '#f59e0b',
                  fontSize: 10,
                  position: 'insideTopRight',
                }}
              />
              <Area
                type="monotone"
                dataKey="confidencePct"
                stroke="#10b981"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#predictionConfidenceGrad)"
                name="Prediction Confidence %"
                dot={(props: any) => {
                  const { cx, cy, payload } = props;
                  if (!payload.isCorrect) {
                    return (
                      <circle
                        key={`dot-err-${payload.id}`}
                        cx={cx}
                        cy={cy}
                        r={5}
                        fill="#ef4444"
                        stroke="#ffffff"
                        strokeWidth={1.5}
                      />
                    );
                  }
                  return (
                    <circle
                      key={`dot-ok-${payload.id}`}
                      cx={cx}
                      cy={cy}
                      r={2.5}
                      fill="#10b981"
                    />
                  );
                }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* TWO-COLUMN GRAPH SECTION: CLASS DISTRIBUTION & CONFIDENCE BREAKDOWN */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CHART 2: OUTPUT CLASS PREDICTION FREQUENCIES (%) */}
        <div
          id="chart-class-distribution"
          className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-xl flex flex-col justify-between"
        >
          <div className="mb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <BarChart2 className="w-5 h-5 text-blue-400" />
              Output Class Distribution & Prediction Percentages
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Total volume and frequency breakdown across model output categories
            </p>
          </div>

          <div className="h-64 sm:h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={currentDataset.classes}
                layout="vertical"
                margin={{ top: 10, right: 30, left: 40, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" horizontal={false} />
                <XAxis
                  type="number"
                  domain={[0, 45]}
                  stroke="#71717a"
                  tick={{ fontSize: 11, fill: '#71717a' }}
                  tickFormatter={(val) => `${val}%`}
                />
                <YAxis
                  type="category"
                  dataKey="className"
                  stroke="#71717a"
                  tick={{ fontSize: 11, fill: '#a1a1aa' }}
                  width={110}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload as (typeof currentDataset.classes)[0];
                      return (
                        <div className="bg-zinc-950 border border-zinc-700 rounded-lg p-2.5 shadow-xl text-xs space-y-1">
                          <div className="font-bold text-white font-mono">{data.className}</div>
                          <div className="text-zinc-400">
                            Prediction Share:{' '}
                            <span className="text-blue-400 font-bold">{data.percentage}%</span>
                          </div>
                          <div className="text-zinc-400">
                            Total Inferences:{' '}
                            <span className="text-zinc-200 font-mono">
                              {data.count.toLocaleString()}
                            </span>
                          </div>
                          <div className="text-zinc-400">
                            Avg Class Confidence:{' '}
                            <span className="text-emerald-400 font-bold">
                              {data.avgConfidence}%
                            </span>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar dataKey="percentage" radius={[0, 4, 4, 0]} name="Prediction Share %">
                  {currentDataset.classes.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* CHART 3: PREDICTION CONFIDENCE DISTRIBUTION (DONUT) */}
        <div
          id="chart-confidence-donut"
          className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-xl flex flex-col justify-between"
        >
          <div className="mb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <PieIcon className="w-5 h-5 text-purple-400" />
              Model Prediction Confidence Distribution (%)
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Proportion of model outputs categorised by certainty thresholds
            </p>
          </div>

          <div className="h-64 sm:h-72 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={currentDataset.confidenceBuckets}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="percentage"
                  nameKey="name"
                >
                  {currentDataset.confidenceBuckets.map((entry, index) => (
                    <Cell key={`donut-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload as (typeof currentDataset.confidenceBuckets)[0];
                      return (
                        <div className="bg-zinc-950 border border-zinc-700 rounded-lg p-2.5 shadow-xl text-xs space-y-1">
                          <div className="font-bold text-white">{data.name}</div>
                          <div className="text-zinc-400">
                            Proportion:{' '}
                            <span className="text-emerald-400 font-bold">{data.percentage}%</span>
                          </div>
                          <div className="text-zinc-400">
                            Total Samples:{' '}
                            <span className="text-zinc-200 font-mono">
                              {data.count.toLocaleString()}
                            </span>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconType="circle"
                  wrapperStyle={{ fontSize: '11px', color: '#a1a1aa' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* TWO-COLUMN GRAPH SECTION: CLEAN VS BACKDOOR ATTACK SHIFT & CLASS-WISE RADAR */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CHART 4: CLEAN BASELINE VS ADVERSARIAL BACKDOOR PREDICTION SHIFT (%) */}
        <div
          id="chart-backdoor-shift"
          className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-xl flex flex-col justify-between"
        >
          <div className="mb-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Target className="w-5 h-5 text-red-400" />
                Clean Baseline vs. Triggered Attack Prediction Shift (%)
              </h3>
              <span className="text-[11px] font-mono text-red-400 bg-red-950/60 border border-red-800/60 px-2 py-0.5 rounded">
                Trojan Impact
              </span>
            </div>
            <p className="text-xs text-zinc-400 mt-0.5">
              Target class prediction distortion when adversarial trigger is introduced to model inputs
            </p>
          </div>

          <div className="h-64 sm:h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={currentDataset.backdoorShift}
                margin={{ top: 10, right: 15, left: -15, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                <XAxis
                  dataKey="className"
                  stroke="#71717a"
                  tick={{ fontSize: 10, fill: '#a1a1aa' }}
                />
                <YAxis
                  stroke="#71717a"
                  domain={[0, 90]}
                  tick={{ fontSize: 11, fill: '#71717a' }}
                  tickFormatter={(val) => `${val}%`}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload as (typeof currentDataset.backdoorShift)[0];
                      return (
                        <div className="bg-zinc-950 border border-zinc-700 rounded-lg p-2.5 shadow-xl text-xs space-y-1">
                          <div className="font-bold text-white font-mono">{data.className}</div>
                          <div className="text-emerald-400">
                            Clean Prediction Share: <strong>{data.cleanPredictionPct}%</strong>
                          </div>
                          <div className="text-red-400">
                            Triggered Attack Share: <strong>{data.triggeredPredictionPct}%</strong>
                          </div>
                          <div className="text-zinc-400 text-[11px]">
                            Displacement Delta:{' '}
                            <strong>
                              {(data.triggeredPredictionPct - data.cleanPredictionPct).toFixed(1)}%
                            </strong>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Legend
                  verticalAlign="top"
                  height={30}
                  iconType="circle"
                  wrapperStyle={{ fontSize: '11px', color: '#a1a1aa' }}
                />
                <Bar
                  dataKey="cleanPredictionPct"
                  name="Clean Baseline Predictions (%)"
                  fill="#10b981"
                  radius={[4, 4, 0, 0]}
                />
                <Bar
                  dataKey="triggeredPredictionPct"
                  name="Triggered / Adversarial Predictions (%)"
                  fill="#ef4444"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* CHART 5: MULTI-AXIS PERFORMANCE RADAR (%) */}
        <div
          id="chart-performance-radar"
          className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-xl flex flex-col justify-between"
        >
          <div className="mb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-emerald-400" />
              Class Performance Metrics & Prediction Precision Radar (%)
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Precision, recall, F1, and confidence percentages across all output classes
            </p>
          </div>

          <div className="h-64 sm:h-72 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData} outerRadius={80}>
                <PolarGrid stroke="#27272a" />
                <PolarAngleAxis dataKey="metric" stroke="#a1a1aa" tick={{ fontSize: 10, fill: '#a1a1aa' }} />
                <PolarRadiusAxis
                  angle={30}
                  domain={[80, 100]}
                  stroke="#71717a"
                  tick={{ fontSize: 9, fill: '#71717a' }}
                />
                {currentDataset.classes.map((cls) => (
                  <Radar
                    key={cls.className}
                    name={cls.className}
                    dataKey={cls.className}
                    stroke={cls.color}
                    fill={cls.color}
                    fillOpacity={0.2}
                  />
                ))}
                <Legend
                  verticalAlign="bottom"
                  height={28}
                  iconType="circle"
                  wrapperStyle={{ fontSize: '10px', color: '#a1a1aa' }}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      return (
                        <div className="bg-zinc-950 border border-zinc-700 rounded-lg p-2.5 shadow-xl text-xs space-y-1">
                          <div className="font-bold text-white">
                            {payload[0].payload.metric}
                          </div>
                          {payload.map((p) => (
                            <div key={p.name} style={{ color: p.color }}>
                              {p.name}: <strong>{Number(p.value).toFixed(1)}%</strong>
                            </div>
                          ))}
                        </div>
                      );
                    }
                    return null;
                  }}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* TWO-COLUMN GRAPH SECTION: CONFUSION ACCURACY & LATENCY CORRELATION */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CHART 6: PREDICTION CONFUSION ACCURACY MATRIX (%) */}
        <div
          id="chart-confusion-matrix"
          className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-xl"
        >
          <div className="mb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-amber-400" />
              Target vs. Predicted Class Alignment Matrix (%)
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Percentage of actual instances mapped to each predicted output category
            </p>
          </div>

          <div className="h-64 sm:h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={currentDataset.confusionMatrix}
                margin={{ top: 10, right: 15, left: -15, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                <XAxis
                  dataKey="actualClass"
                  stroke="#71717a"
                  tick={{ fontSize: 10, fill: '#a1a1aa' }}
                />
                <YAxis
                  stroke="#71717a"
                  domain={[0, 100]}
                  tick={{ fontSize: 11, fill: '#71717a' }}
                  tickFormatter={(val) => `${val}%`}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const actual = payload[0].payload.actualClass;
                      return (
                        <div className="bg-zinc-950 border border-zinc-700 rounded-lg p-2.5 shadow-xl text-xs space-y-1">
                          <div className="font-bold text-white">Actual Class: {actual}</div>
                          {payload.map((p) => (
                            <div key={p.name} style={{ color: p.color }}>
                              Predicted as {p.name}: <strong>{Number(p.value).toFixed(1)}%</strong>
                            </div>
                          ))}
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Legend
                  verticalAlign="top"
                  height={30}
                  iconType="circle"
                  wrapperStyle={{ fontSize: '10px', color: '#a1a1aa' }}
                />
                {currentDataset.classes.map((cls) => (
                  <Bar
                    key={cls.className}
                    dataKey={cls.className}
                    name={cls.className}
                    fill={cls.color}
                    radius={[4, 4, 0, 0]}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* CHART 7: INFERENCE LATENCY (MS) VS PREDICTION CONFIDENCE (%) */}
        <div
          id="chart-latency-confidence"
          className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-xl"
        >
          <div className="mb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Zap className="w-5 h-5 text-cyan-400" />
              Inference Compute Latency vs. Prediction Confidence
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Dual-axis correlation of execution time (ms) and output probability (%) across inferences
            </p>
          </div>

          <div className="h-64 sm:h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart
                data={filteredPredictions}
                margin={{ top: 10, right: 15, left: -10, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                <XAxis
                  dataKey="sampleIndex"
                  stroke="#71717a"
                  tick={{ fontSize: 10, fill: '#71717a' }}
                  tickFormatter={(val) => `#${val}`}
                />
                <YAxis
                  yAxisId="left"
                  stroke="#10b981"
                  domain={[75, 100]}
                  tick={{ fontSize: 10, fill: '#10b981' }}
                  tickFormatter={(val) => `${val}%`}
                />
                <YAxis
                  yAxisId="right"
                  orientation="right"
                  stroke="#06b6d4"
                  domain={[10, 35]}
                  tick={{ fontSize: 10, fill: '#06b6d4' }}
                  tickFormatter={(val) => `${val}ms`}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload as (typeof filteredPredictions)[0];
                      return (
                        <div className="bg-zinc-950 border border-zinc-700 rounded-lg p-2.5 shadow-xl text-xs space-y-1">
                          <div className="font-bold text-white font-mono">
                            Sample #{data.sampleIndex}
                          </div>
                          <div className="text-emerald-400">
                            Confidence: <strong>{data.confidencePct.toFixed(1)}%</strong>
                          </div>
                          <div className="text-cyan-400">
                            Latency: <strong>{data.latencyMs} ms</strong>
                          </div>
                          <div className="text-zinc-400">
                            Predicted: <strong>{data.predictedClass}</strong>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Legend
                  verticalAlign="top"
                  height={30}
                  iconType="circle"
                  wrapperStyle={{ fontSize: '11px', color: '#a1a1aa' }}
                />
                <Bar
                  yAxisId="right"
                  dataKey="latencyMs"
                  name="Latency (ms)"
                  fill="#06b6d4"
                  fillOpacity={0.6}
                  radius={[3, 3, 0, 0]}
                />
                <Line
                  yAxisId="left"
                  type="monotone"
                  dataKey="confidencePct"
                  name="Confidence %"
                  stroke="#10b981"
                  strokeWidth={2}
                  dot={{ r: 2, fill: '#10b981' }}
                />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
