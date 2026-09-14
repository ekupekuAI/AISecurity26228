export interface TimeSeriesPoint {
  date: string;
  fullDate: string;
  target: number; // Ground truth target daily mean
  prediction: number; // Model prediction daily mean
  lowerBound: number;
  upperBound: number;
  residual: number; // prediction - target
  absError: number;
  confidence: number;
  modelCalls: number;
}

export interface FeatureDistributionStats {
  mean: number;
  std: number;
  min: number;
  q25: number;
  median: number;
  q75: number;
  max: number;
}

export interface FeatureDriftItem {
  id: string;
  feature: string;
  displayName: string;
  type: 'num' | 'cat';
  referenceDist: number[]; // Sparkline histogram bar heights
  currentDist: number[];
  driftStatus: 'Detected' | 'Not Detected';
  statTest: string;
  driftScore: number;
  threshold: number;
  referenceStats: FeatureDistributionStats;
  currentStats: FeatureDistributionStats;
  recommendation: string;
}

export interface TestSuiteItem {
  id: string;
  name: string;
  category: 'PREDICTION_ACCURACY' | 'DRIFT_BOUNDS' | 'DATA_QUALITY' | 'INFERENCE_LATENCY';
  status: 'PASSED' | 'FAILED' | 'WARNING';
  metric: string;
  currentValue: string;
  expectedThreshold: string;
  description: string;
}

export interface ModelComparisonItem {
  metric: string;
  category: string;
  baselineModel: number | string; // e.g. YOLOv7 Baseline
  championModel: number | string; // YOLOv8-IR v2.4 (Active)
  challengerModel: number | string; // YOLOv8-Thermal-Enhanced v2.5
  unit: string;
  betterDirection: 'higher' | 'lower';
}

// 31-Day Time Series of Target (Ground Truth Daily Mean) vs Model Prediction (Daily Mean)
export const EVALUATION_TIME_SERIES: TimeSeriesPoint[] = [
  { date: 'Jan 31', fullDate: '2026-01-31', target: 132, prediction: 110, lowerBound: 114, upperBound: 150, residual: -22, absError: 22, confidence: 0.84, modelCalls: 590 },
  { date: 'Feb 01', fullDate: '2026-02-01', target: 146, prediction: 119, lowerBound: 128, upperBound: 164, residual: -27, absError: 27, confidence: 0.86, modelCalls: 620 },
  { date: 'Feb 02', fullDate: '2026-02-02', target: 182, prediction: 152, lowerBound: 164, upperBound: 200, residual: -30, absError: 30, confidence: 0.89, modelCalls: 710 },
  { date: 'Feb 03', fullDate: '2026-02-03', target: 185, prediction: 154, lowerBound: 167, upperBound: 203, residual: -31, absError: 31, confidence: 0.87, modelCalls: 745 },
  { date: 'Feb 04', fullDate: '2026-02-04', target: 152, prediction: 140, lowerBound: 134, upperBound: 170, residual: -12, absError: 12, confidence: 0.91, modelCalls: 680 },
  { date: 'Feb 05', fullDate: '2026-02-05', target: 168, prediction: 154, lowerBound: 150, upperBound: 186, residual: -14, absError: 14, confidence: 0.90, modelCalls: 695 },
  { date: 'Feb 06', fullDate: '2026-02-06', target: 114, prediction: 118, lowerBound: 96, upperBound: 132, residual: 4, absError: 4, confidence: 0.93, modelCalls: 540 },
  { date: 'Feb 07', fullDate: '2026-02-07', target: 118, prediction: 98, lowerBound: 100, upperBound: 136, residual: -20, absError: 20, confidence: 0.88, modelCalls: 560 },
  { date: 'Feb 08', fullDate: '2026-02-08', target: 158, prediction: 138, lowerBound: 140, upperBound: 176, residual: -20, absError: 20, confidence: 0.87, modelCalls: 670 },
  { date: 'Feb 09', fullDate: '2026-02-09', target: 174, prediction: 150, lowerBound: 156, upperBound: 192, residual: -24, absError: 24, confidence: 0.89, modelCalls: 720 },
  { date: 'Feb 10', fullDate: '2026-02-10', target: 116, prediction: 114, lowerBound: 98, upperBound: 134, residual: -2, absError: 2, confidence: 0.94, modelCalls: 530 },
  { date: 'Feb 11', fullDate: '2026-02-11', target: 155, prediction: 137, lowerBound: 137, upperBound: 173, residual: -18, absError: 18, confidence: 0.90, modelCalls: 640 },
  { date: 'Feb 12', fullDate: '2026-02-12', target: 156, prediction: 140, lowerBound: 138, upperBound: 174, residual: -16, absError: 16, confidence: 0.89, modelCalls: 655 },
  { date: 'Feb 13', fullDate: '2026-02-13', target: 82, prediction: 84, lowerBound: 64, upperBound: 100, residual: 2, absError: 2, confidence: 0.92, modelCalls: 480 },
  { date: 'Feb 14', fullDate: '2026-02-14', target: 62, prediction: 88, lowerBound: 44, upperBound: 80, residual: 26, absError: 26, confidence: 0.81, modelCalls: 460 },
  { date: 'Feb 15', fullDate: '2026-02-15', target: 136, prediction: 115, lowerBound: 118, upperBound: 154, residual: -21, absError: 21, confidence: 0.87, modelCalls: 630 },
  { date: 'Feb 16', fullDate: '2026-02-16', target: 155, prediction: 145, lowerBound: 137, upperBound: 173, residual: -10, absError: 10, confidence: 0.92, modelCalls: 685 },
  { date: 'Feb 17', fullDate: '2026-02-17', target: 166, prediction: 152, lowerBound: 148, upperBound: 184, residual: -14, absError: 14, confidence: 0.90, modelCalls: 710 },
  { date: 'Feb 18', fullDate: '2026-02-18', target: 122, prediction: 125, lowerBound: 104, upperBound: 140, residual: 3, absError: 3, confidence: 0.93, modelCalls: 590 },
  { date: 'Feb 19', fullDate: '2026-02-19', target: 168, prediction: 162, lowerBound: 150, upperBound: 186, residual: -6, absError: 6, confidence: 0.95, modelCalls: 730 },
  { date: 'Feb 20', fullDate: '2026-02-20', target: 172, prediction: 164, lowerBound: 154, upperBound: 190, residual: -8, absError: 8, confidence: 0.94, modelCalls: 740 },
  { date: 'Feb 21', fullDate: '2026-02-21', target: 108, prediction: 102, lowerBound: 90, upperBound: 126, residual: -6, absError: 6, confidence: 0.92, modelCalls: 510 },
  { date: 'Feb 22', fullDate: '2026-02-22', target: 130, prediction: 114, lowerBound: 112, upperBound: 148, residual: -16, absError: 16, confidence: 0.89, modelCalls: 610 },
  { date: 'Feb 23', fullDate: '2026-02-23', target: 155, prediction: 142, lowerBound: 137, upperBound: 173, residual: -13, absError: 13, confidence: 0.91, modelCalls: 675 },
  { date: 'Feb 24', fullDate: '2026-02-24', target: 180, prediction: 158, lowerBound: 162, upperBound: 198, residual: -22, absError: 22, confidence: 0.88, modelCalls: 725 },
  { date: 'Feb 25', fullDate: '2026-02-25', target: 198, prediction: 162, lowerBound: 180, upperBound: 216, residual: -36, absError: 36, confidence: 0.84, modelCalls: 760 },
  { date: 'Feb 26', fullDate: '2026-02-26', target: 206, prediction: 164, lowerBound: 188, upperBound: 224, residual: -42, absError: 42, confidence: 0.82, modelCalls: 780 },
  { date: 'Feb 27', fullDate: '2026-02-27', target: 148, prediction: 142, lowerBound: 130, upperBound: 166, residual: -6, absError: 6, confidence: 0.93, modelCalls: 660 },
  { date: 'Feb 28', fullDate: '2026-02-28', target: 126, prediction: 130, lowerBound: 108, upperBound: 144, residual: 4, absError: 4, confidence: 0.91, modelCalls: 595 },
  { date: 'Mar 01', fullDate: '2026-03-01', target: 112, prediction: 122, lowerBound: 94, upperBound: 130, residual: 10, absError: 10, confidence: 0.90, modelCalls: 550 },
];

export const FEATURE_DRIFT_REPORT: FeatureDriftItem[] = [
  {
    id: 'f-1',
    feature: 'prediction',
    displayName: 'Target Prediction (Daily Mean)',
    type: 'num',
    // Reference distribution histogram bars
    referenceDist: [12, 65, 140, 115, 88, 62, 45, 28, 18, 12, 8, 5, 2, 1],
    // Current distribution histogram bars shifted right
    currentDist: [4, 18, 52, 98, 134, 148, 112, 84, 58, 42, 28, 19, 11, 6],
    driftStatus: 'Detected',
    statTest: 'K-S p_value',
    driftScore: 0.019459,
    threshold: 0.05,
    referenceStats: { mean: 127.4, std: 31.8, min: 45, q25: 102, median: 124, q75: 151, max: 212 },
    currentStats: { mean: 148.9, std: 39.4, min: 62, q25: 119, median: 146, q75: 174, max: 244 },
    recommendation: 'Ground truth prediction distribution exhibits significant right-skew (+16.8%). Recalibrate detection threshold prior to deployment.',
  },
  {
    id: 'f-2',
    feature: 'weekday',
    displayName: 'Mission Temporal Index (Weekday)',
    type: 'num',
    referenceDist: [100, 100, 100, 100, 100, 100, 100],
    currentDist: [100, 100, 100, 100, 100, 100, 100],
    driftStatus: 'Not Detected',
    statTest: 'K-S p_value',
    driftScore: 1.0,
    threshold: 0.05,
    referenceStats: { mean: 3.0, std: 2.0, min: 0, q25: 1, median: 3, q75: 5, max: 6 },
    currentStats: { mean: 3.0, std: 2.0, min: 0, q25: 1, median: 3, q75: 5, max: 6 },
    recommendation: 'Temporal operational sampling remains uniformly balanced across patrol cycles.',
  },
  {
    id: 'f-3',
    feature: 'hr',
    displayName: 'Operational Hour (0 - 23)',
    type: 'num',
    referenceDist: [45, 60, 80, 95, 110, 105, 90, 85, 90, 100, 110, 105, 95, 80],
    currentDist: [46, 59, 81, 94, 109, 106, 91, 84, 89, 101, 111, 104, 96, 79],
    driftStatus: 'Not Detected',
    statTest: 'K-S p_value',
    driftScore: 1.0,
    threshold: 0.05,
    referenceStats: { mean: 11.5, std: 6.9, min: 0, q25: 6, median: 12, q75: 17, max: 23 },
    currentStats: { mean: 11.5, std: 6.9, min: 0, q25: 6, median: 12, q75: 17, max: 23 },
    recommendation: 'Hour-of-day sampling aligns perfectly with baseline surveillance roster.',
  },
  {
    id: 'f-4',
    feature: 'windspeed',
    displayName: 'Sensor Airflow & Windspeed (m/s)',
    type: 'num',
    referenceDist: [15, 42, 95, 138, 150, 128, 92, 60, 35, 20, 10, 5, 2, 1],
    currentDist: [2, 10, 28, 65, 98, 135, 152, 140, 110, 75, 48, 26, 12, 5],
    driftStatus: 'Detected',
    statTest: 'K-S p_value',
    driftScore: 0.000001,
    threshold: 0.05,
    referenceStats: { mean: 12.8, std: 4.6, min: 2.1, q25: 9.4, median: 12.5, q75: 15.8, max: 28.4 },
    currentStats: { mean: 18.2, std: 5.8, min: 4.0, q25: 14.1, median: 17.9, q75: 22.0, max: 34.2 },
    recommendation: 'High wind velocity detected at forward surveillance mast (+42.1%). Camera vibration compensation recommended.',
  },
  {
    id: 'f-5',
    feature: 'temp',
    displayName: 'Ambient Thermal Temperature (°C)',
    type: 'num',
    referenceDist: [8, 22, 50, 88, 124, 145, 132, 98, 65, 38, 20, 10, 4, 1],
    currentDist: [2, 8, 22, 45, 80, 115, 148, 160, 138, 102, 64, 35, 18, 6],
    driftStatus: 'Detected',
    statTest: 'K-S p_value',
    driftScore: 0.002840,
    threshold: 0.05,
    referenceStats: { mean: 20.4, std: 6.2, min: 4.5, q25: 15.8, median: 20.1, q75: 24.9, max: 36.2 },
    currentStats: { mean: 25.1, std: 6.9, min: 8.2, q25: 20.4, median: 25.0, q75: 29.8, max: 41.5 },
    recommendation: 'Thermal temperature shifted warmer (+23.0%), impacting infrared sensor sensor-to-noise ratio.',
  },
  {
    id: 'f-6',
    feature: 'humidity',
    displayName: 'Relative Atmospheric Humidity (%)',
    type: 'num',
    referenceDist: [10, 25, 55, 90, 125, 145, 130, 100, 70, 42, 22, 12, 5, 2],
    currentDist: [12, 24, 54, 91, 123, 144, 131, 99, 71, 43, 21, 11, 6, 2],
    driftStatus: 'Not Detected',
    statTest: 'K-S p_value',
    driftScore: 0.871400,
    threshold: 0.05,
    referenceStats: { mean: 62.4, std: 14.8, min: 18.0, q25: 52.0, median: 63.0, q75: 73.5, max: 98.0 },
    currentStats: { mean: 62.1, std: 14.9, min: 17.5, q25: 51.5, median: 62.8, q75: 73.0, max: 97.5 },
    recommendation: 'Humidity levels remain nominal within optical calibration tolerance.',
  },
  {
    id: 'f-7',
    feature: 'casual',
    displayName: 'Foreground Confidence Score',
    type: 'num',
    referenceDist: [60, 95, 130, 140, 115, 80, 52, 34, 20, 12, 8, 4, 2, 1],
    currentDist: [20, 45, 85, 120, 140, 135, 105, 78, 52, 35, 22, 14, 8, 4],
    driftStatus: 'Detected',
    statTest: 'Wasserstein dist',
    driftScore: 0.048200,
    threshold: 0.05,
    referenceStats: { mean: 35.8, std: 24.2, min: 1.0, q25: 16.0, median: 31.0, q75: 52.0, max: 110.0 },
    currentStats: { mean: 47.6, std: 28.5, min: 3.0, q25: 25.0, median: 44.0, q75: 68.0, max: 135.0 },
    recommendation: 'Elevated foreground confidence variance indicates increased peripheral clutter in active sectors.',
  },
];

export const TEST_SUITES_DATA: TestSuiteItem[] = [
  {
    id: 'test-1',
    name: 'Mean Absolute Percentage Error (MAPE)',
    category: 'PREDICTION_ACCURACY',
    status: 'PASSED',
    metric: 'MAPE',
    currentValue: '8.42%',
    expectedThreshold: '≤ 15.0%',
    description: 'Verifies average prediction error stays within the strict military specification ceiling.',
  },
  {
    id: 'test-2',
    name: 'Share of Drifted Features Tolerance',
    category: 'DRIFT_BOUNDS',
    status: 'FAILED',
    metric: 'Drifted Share',
    currentValue: '57.1% (4 of 7)',
    expectedThreshold: '< 30.0%',
    description: 'Drift detected across prediction, windspeed, temperature, and foreground features.',
  },
  {
    id: 'test-3',
    name: 'Null / NaN Inferences Guarantee',
    category: 'DATA_QUALITY',
    status: 'PASSED',
    metric: 'NaN Ratio',
    currentValue: '0.00%',
    expectedThreshold: '= 0.00%',
    description: 'All 1,428 model inferences yielded valid floating-point tensors without numerical overflow.',
  },
  {
    id: 'test-4',
    name: 'P99 Real-time Inference Latency',
    category: 'INFERENCE_LATENCY',
    status: 'PASSED',
    metric: 'P99 Latency',
    currentValue: '18.4 ms',
    expectedThreshold: '≤ 35.0 ms',
    description: 'Real-time inference speed complies with 50 FPS autonomous vision pipeline requirements.',
  },
  {
    id: 'test-5',
    name: 'Prediction Quantile Range Envelope',
    category: 'PREDICTION_ACCURACY',
    status: 'PASSED',
    metric: 'Quantile [5%, 95%]',
    currentValue: '[68, 196]',
    expectedThreshold: '[40, 230]',
    description: 'Model predictions fall strictly within calibrated operational bounds.',
  },
  {
    id: 'test-6',
    name: 'Ground Truth Coverage Ratio',
    category: 'DATA_QUALITY',
    status: 'PASSED',
    metric: 'Coverage',
    currentValue: '99.4%',
    expectedThreshold: '≥ 95.0%',
    description: 'Synchronized telemetry available for 30 of 30 patrol analysis periods.',
  },
];

export const MODEL_COMPARISON_DATA: ModelComparisonItem[] = [
  {
    metric: 'Mean Absolute Error (MAE)',
    category: 'Prediction Accuracy',
    baselineModel: '14.8',
    championModel: '8.4',
    challengerModel: '6.9',
    unit: 'count',
    betterDirection: 'lower',
  },
  {
    metric: 'R² Correlation Score',
    category: 'Prediction Accuracy',
    baselineModel: '0.812',
    championModel: '0.914',
    challengerModel: '0.942',
    unit: 'ratio',
    betterDirection: 'higher',
  },
  {
    metric: 'Share of Drifted Features',
    category: 'Drift Robustness',
    baselineModel: '71.4%',
    championModel: '57.1%',
    challengerModel: '28.6%',
    unit: '%',
    betterDirection: 'lower',
  },
  {
    metric: 'Inference Latency (Mean)',
    category: 'Operational Speed',
    baselineModel: '28.5 ms',
    championModel: '14.2 ms',
    challengerModel: '16.8 ms',
    unit: 'ms',
    betterDirection: 'lower',
  },
  {
    metric: 'Trojan / Backdoor Resistance',
    category: 'Security Assurance',
    baselineModel: '84.0%',
    championModel: '99.2%',
    challengerModel: '99.6%',
    unit: '%',
    betterDirection: 'higher',
  },
  {
    metric: 'Zip Slip & Path Traversal Proofing',
    category: 'Security Assurance',
    baselineModel: 'VERIFIED',
    championModel: 'VERIFIED',
    challengerModel: 'VERIFIED',
    unit: 'status',
    betterDirection: 'higher',
  },
];
