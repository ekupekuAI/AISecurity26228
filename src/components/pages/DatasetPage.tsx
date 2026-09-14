import React, { useState } from 'react';
import JSZip from 'jszip';
import {
  UploadCloud,
  FileArchive,
  Database,
  AlertTriangle,
  Copy,
  Layers,
  BarChart3,
  Search,
  CheckCircle2,
  Sparkles,
} from 'lucide-react';
import { DatasetAnalysisResult, Finding } from '../../types.js';
import { analyzeDataset } from '../../api/client.js';
import { StatusBadge } from '../StatusBadge.js';
import { SeverityBadge } from '../SeverityBadge.js';

interface DatasetPageProps {
  onFindingClick: (finding: Finding) => void;
  onRefreshStats: () => void;
}

export const DatasetPage: React.FC<DatasetPageProps> = ({ onFindingClick, onRefreshStats }) => {
  const [file, setFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<DatasetAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const runAnalysis = async () => {
    if (!file) return;
    setIsAnalyzing(true);
    setError(null);
    try {
      const result = await analyzeDataset(file);
      setAnalysisResult(result);
      onRefreshStats();
    } catch (err) {
      setError((err as Error).message || 'Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Helper to create a test synthetic dataset zip in the browser for instant testing
  const createTestArchive = async (withDuplicates: boolean, withCorrupt: boolean) => {
    try {
      const zip = new JSZip();

      // Sample 1x1 valid PNG bytes
      const validPngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      const validPngBytes = Uint8Array.from(atob(validPngBase64), c => c.charCodeAt(0));

      zip.file('train/pedestrian/ped_001.png', validPngBytes);
      zip.file('train/pedestrian/ped_002.png', validPngBytes); // Exact duplicate
      zip.file('train/vehicles/car_001.png', validPngBytes);
      zip.file('train/vehicles/car_002.png', validPngBytes);
      zip.file('train/vehicles/car_003.png', validPngBytes);
      zip.file('train/vehicles/car_004.png', validPngBytes);
      zip.file('train/vehicles/car_005.png', validPngBytes);
      zip.file('train/vehicles/car_006.png', validPngBytes);
      zip.file('train/vehicles/car_007.png', validPngBytes);
      zip.file('train/vehicles/car_008.png', validPngBytes); // Class skew 8:1

      if (withCorrupt) {
        zip.file('train/damaged/corrupt_header.png', new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
      }

      zip.file('metadata/contributors.csv', 'filename,user_id,source\ncar_001.png,rig_alpha,sensor_lab\n');

      const blob = await zip.generateAsync({ type: 'blob' });
      const testFile = new File([blob], withCorrupt ? 'test_corrupted_dataset.zip' : 'test_synthetic_cv_dataset.zip', {
        type: 'application/zip',
      });
      setFile(testFile);
    } catch {
      const dummy = new File(['Dummy dataset test buffer'], 'sample_dataset.zip', { type: 'application/zip' });
      setFile(dummy);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-zinc-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Database className="h-5 w-5 text-emerald-400" />
            <h2 className="text-lg font-bold text-zinc-100">Dataset Integrity &amp; Poisoning Forensics</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Forensic analysis for duplicate poisoning, corrupted images, extreme class imbalance, and out-of-distribution artifacts.
          </p>
        </div>

        {/* Test Generators */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => createTestArchive(true, false)}
            className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
          >
            <Sparkles className="h-3 w-3 text-emerald-400" /> Load Test Archive
          </button>
          <button
            onClick={() => createTestArchive(true, true)}
            className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
          >
            <AlertTriangle className="h-3 w-3 text-amber-400" /> Test with Corrupted Image
          </button>
        </div>
      </div>

      {/* Upload Zone */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-8 text-center transition-all ${
          dragActive
            ? 'border-emerald-500 bg-emerald-950/20'
            : 'border-zinc-800 bg-zinc-900/40 hover:border-zinc-700'
        }`}
      >
        <input
          type="file"
          id="dataset-file-input"
          onChange={handleFileChange}
          accept=".zip,.png,.jpg,.jpeg,.webp"
          className="hidden"
        />

        <div className="rounded-full bg-zinc-800/80 p-3 text-zinc-300 mb-3">
          <UploadCloud className="h-6 w-6 text-emerald-400" />
        </div>

        <div className="space-y-1">
          <p className="text-sm font-medium text-zinc-200">
            {file ? file.name : 'Drop training dataset archive here, or browse'}
          </p>
          <p className="text-xs text-zinc-400 font-mono">
            {file
              ? `${(file.size / (1024 * 1024)).toFixed(2)} MB • ${file.type || 'ZIP archive'}`
              : 'Supports .ZIP (image directories), PNG, JPEG, WebP (up to 500MB)'}
          </p>
        </div>

        <div className="mt-4 flex items-center gap-3">
          <label
            htmlFor="dataset-file-input"
            className="cursor-pointer rounded-lg border border-zinc-700 bg-zinc-800 px-3.5 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-700 transition"
          >
            Select File
          </label>
          {file && (
            <button
              onClick={runAnalysis}
              disabled={isAnalyzing}
              className="rounded-lg bg-emerald-600 hover:bg-emerald-500 px-4 py-1.5 text-xs font-semibold text-white transition disabled:opacity-50 flex items-center gap-1.5 shadow"
            >
              {isAnalyzing ? (
                <>
                  <span className="h-3 w-3 animate-spin rounded-full border border-white border-t-transparent" />
                  Running Forensics...
                </>
              ) : (
                <>
                  <Search className="h-3.5 w-3.5" /> Launch Forensic Scan
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-800 bg-rose-950/40 p-3 text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Analysis Results */}
      {analysisResult && (
        <div className="space-y-6 pt-2">
          {/* Top Result Banner */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <StatusBadge status={analysisResult.status} size="lg" />
                <span className="text-sm font-mono font-bold text-zinc-100">{analysisResult.filename}</span>
              </div>
              <p className="text-xs font-mono text-zinc-400 break-all">
                SHA-256: {analysisResult.sha256}
              </p>
            </div>

            <div className="flex items-center gap-4">
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-right">
                <span className="text-[10px] text-zinc-400 uppercase font-mono block">Dataset Risk Score</span>
                <span
                  className={`font-mono text-2xl font-bold ${
                    analysisResult.datasetRisk > 50
                      ? 'text-rose-400'
                      : analysisResult.datasetRisk > 20
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {analysisResult.datasetRisk}/100
                </span>
              </div>
            </div>
          </div>

          {/* Metric Stats Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
              <span className="text-zinc-400 text-xs block">Total Samples</span>
              <span className="text-lg font-bold text-zinc-100">{analysisResult.totalSamples}</span>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
              <span className="text-zinc-400 text-xs block">Corrupted Files</span>
              <span
                className={`text-lg font-bold ${
                  analysisResult.corruptedFiles > 0 ? 'text-rose-400' : 'text-emerald-400'
                }`}
              >
                {analysisResult.corruptedFiles}
              </span>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
              <span className="text-zinc-400 text-xs block">Duplicate Groups</span>
              <span
                className={`text-lg font-bold ${
                  analysisResult.duplicateFiles.length > 0 ? 'text-amber-400' : 'text-emerald-400'
                }`}
              >
                {analysisResult.duplicateFiles.length}
              </span>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
              <span className="text-zinc-400 text-xs block">Near-Duplicate Pairs</span>
              <span className="text-lg font-bold text-zinc-300">
                {analysisResult.nearDuplicateCandidates.length}
              </span>
            </div>
          </div>

          {/* Class Distribution & Outliers */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Class Distribution Bar Chart */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-3">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <BarChart3 className="h-4 w-4 text-emerald-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Inferred Class Distribution
                </h3>
              </div>
              <div className="space-y-2">
                {Object.keys(analysisResult.classDistribution).length > 0 ? (
                  Object.entries(analysisResult.classDistribution).map(([cls, count]) => {
                    const total = Math.max(1, analysisResult.totalSamples);
                    const countNum = typeof count === 'number' ? count : Number(count);
                    const pct = Math.round((countNum / total) * 100);
                    return (
                      <div key={cls} className="space-y-1 text-xs font-mono">
                        <div className="flex justify-between text-zinc-300">
                          <span>{cls}</span>
                          <span>
                            {count} ({pct}%)
                          </span>
                        </div>
                        <div className="h-1.5 w-full rounded-full bg-zinc-800 overflow-hidden">
                          <div
                            className="h-full bg-emerald-500 rounded-full"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <p className="text-xs text-zinc-400 font-mono py-4 text-center">
                    Single sample or unclassified archive.
                  </p>
                )}
              </div>
            </div>

            {/* Exact Duplicates & Near-Duplicates */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-3">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <Copy className="h-4 w-4 text-amber-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Exact Duplicate Findings
                </h3>
              </div>

              <div className="space-y-2 max-h-[190px] overflow-y-auto pr-1">
                {analysisResult.duplicateFiles.length > 0 ? (
                  analysisResult.duplicateFiles.map((dup, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-zinc-800 bg-zinc-950 p-2.5 text-xs font-mono space-y-1"
                    >
                      <div className="flex justify-between items-center text-amber-400">
                        <span>Group #{idx + 1} ({dup.sampleCount} copies)</span>
                        <span className="text-[10px] text-zinc-400 truncate max-w-[120px]">{dup.hash}</span>
                      </div>
                      <div className="text-[11px] text-zinc-400 space-y-0.5">
                        {dup.filenames.map((fn, fIdx) => (
                          <div key={fIdx} className="truncate">• {fn}</div>
                        ))}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="py-6 text-center text-zinc-400 text-xs font-mono flex flex-col items-center gap-1">
                    <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                    <span>No exact bit-for-bit duplicates found in this archive.</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Forensic Evidence Table */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 text-purple-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Detected Findings ({analysisResult.findings.length})
                </h3>
              </div>
              <span className="text-[11px] text-zinc-400 font-mono">Click any finding to inspect evidence</span>
            </div>

            {analysisResult.findings.length > 0 ? (
              <div className="divide-y divide-zinc-800">
                {analysisResult.findings.map(f => (
                  <div
                    key={f.id}
                    onClick={() => onFindingClick(f)}
                    className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-zinc-800/30 px-2 rounded cursor-pointer transition"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.severity} size="sm" />
                        <span className="font-mono text-xs font-bold text-zinc-200">{f.findingId}</span>
                        <span className="text-zinc-400 text-xs font-mono">({(f.confidence * 100).toFixed(0)}% conf)</span>
                      </div>
                      <p className="text-xs text-zinc-300">{f.explanation}</p>
                      <p className="text-[11px] text-zinc-400 font-mono truncate max-w-xl">Asset: {f.affectedAsset}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <span className="text-xs text-emerald-400 font-mono hover:underline">
                        Inspect Evidence &rarr;
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-6 text-center text-zinc-400 text-xs font-mono">
                No security flaws, corruptions, or dataset anomalies identified.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
