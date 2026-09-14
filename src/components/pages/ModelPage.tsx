import React, { useState } from 'react';
import JSZip from 'jszip';
import {
  UploadCloud,
  Cpu,
  ShieldCheck,
  AlertOctagon,
  FileCode,
  ShieldAlert,
  Search,
  Sparkles,
  Info,
} from 'lucide-react';
import { Finding, ModelAnalysisResult } from '../../types.js';
import { analyzeModel } from '../../api/client.js';
import { StatusBadge } from '../StatusBadge.js';
import { SeverityBadge } from '../SeverityBadge.js';

interface ModelPageProps {
  onFindingClick: (finding: Finding) => void;
  onRefreshStats: () => void;
}

export const ModelPage: React.FC<ModelPageProps> = ({ onFindingClick, onRefreshStats }) => {
  const [file, setFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [modelResult, setModelResult] = useState<ModelAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    else if (e.type === 'dragleave') setDragActive(false);
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
      const result = await analyzeModel(file);
      setModelResult(result);
      onRefreshStats();
    } catch (err) {
      setError((err as Error).message || 'Model analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Quick test generators
  const loadTestModel = async (type: 'SAFE_TORCH' | 'SAFE_ONNX' | 'MALICIOUS_PICKLE' | 'UNSUPPORTED') => {
    if (type === 'SAFE_TORCH') {
      try {
        const zip = new JSZip();
        zip.file('model/version', '3\n');
        zip.file('model/data.pkl', 'fake-safe-torchscript-bytecode\n');
        zip.file('model/constants.pkl', 'resnet-vision-weights\n');
        const blob = await zip.generateAsync({ type: 'blob' });
        setFile(new File([blob], 'resnet50_torchscript_model.pt', { type: 'application/octet-stream' }));
      } catch {
        setFile(new File(['fake torch model weights'], 'resnet50_torchscript_model.pt', { type: 'application/octet-stream' }));
      }
    } else if (type === 'SAFE_ONNX') {
      // ONNX protobuf wire format starting with valid header byte 0x08
      const onnxHeader = new Uint8Array([0x08, 0x01, 0x12, 0x08, 0x6f, 0x6e, 0x6e, 0x78, 0x5f, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65]);
      setFile(new File([onnxHeader], 'yolov8_detector_graph.onnx', { type: 'application/octet-stream' }));
    } else if (type === 'MALICIOUS_PICKLE') {
      // Pickle payload containing "posix\nsystem" or "cos\nsystem" code execution vector
      const exploitPayload = new TextEncoder().encode(
        "cos\nsystem\n(S'rm -rf /tmp/test'\ntR. (malicious trojan exploit vector)"
      );
      setFile(new File([exploitPayload], 'backdoor_trojan_checkpoint.pt', { type: 'application/octet-stream' }));
    } else if (type === 'UNSUPPORTED') {
      const text = new TextEncoder().encode("import tensorflow as tf\nmodel = tf.keras.models.Sequential()\n");
      setFile(new File([text], 'legacy_keras_model.h5', { type: 'application/octet-stream' }));
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-zinc-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Cpu className="h-5 w-5 text-emerald-400" />
            <h2 className="text-lg font-bold text-zinc-100">AI Model Integrity &amp; Backdoor Assurance</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Safe static inspection of neural network checkpoints (.pt, .pth, .onnx) for serialization exploits and backdoor triggers.
          </p>
        </div>

        {/* Test Model Selector */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => loadTestModel('SAFE_TORCH')}
            className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
          >
            <Sparkles className="h-3 w-3 text-emerald-400" /> Safe PyTorch .pt
          </button>
          <button
            onClick={() => loadTestModel('SAFE_ONNX')}
            className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
          >
            <ShieldCheck className="h-3 w-3 text-cyan-400" /> Safe ONNX .onnx
          </button>
          <button
            onClick={() => loadTestModel('MALICIOUS_PICKLE')}
            className="rounded bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/80 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
          >
            <AlertOctagon className="h-3 w-3 text-rose-400" /> Malicious Pickle .pt
          </button>
          <button
            onClick={() => loadTestModel('UNSUPPORTED')}
            className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
          >
            <Info className="h-3 w-3 text-amber-400" /> Unsupported Format
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
          id="model-file-input"
          onChange={handleFileChange}
          accept=".pt,.pth,.onnx"
          className="hidden"
        />

        <div className="rounded-full bg-zinc-800/80 p-3 text-zinc-300 mb-3">
          <UploadCloud className="h-6 w-6 text-emerald-400" />
        </div>

        <div className="space-y-1">
          <p className="text-sm font-medium text-zinc-200">
            {file ? file.name : 'Drop neural network checkpoint here, or browse'}
          </p>
          <p className="text-xs text-zinc-400 font-mono">
            {file
              ? `${(file.size / (1024 * 1024)).toFixed(2)} MB • ${file.name.split('.').pop()?.toUpperCase()} format`
              : 'Supports .pt, .pth (PyTorch / TorchScript) and .onnx (Open Neural Network Exchange)'}
          </p>
        </div>

        <div className="mt-4 flex items-center gap-3">
          <label
            htmlFor="model-file-input"
            className="cursor-pointer rounded-lg border border-zinc-700 bg-zinc-800 px-3.5 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-700 transition"
          >
            Select Model
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
                  Inspecting Checkpoint...
                </>
              ) : (
                <>
                  <Search className="h-3.5 w-3.5" /> Launch Security Inspection
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-800 bg-rose-950/40 p-3 text-xs text-rose-300 flex items-center gap-2">
          <AlertOctagon className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Analysis Results */}
      {modelResult && (
        <div className="space-y-6 pt-2">
          {/* Top Result Banner */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <StatusBadge status={modelResult.status} size="lg" />
                <span className="text-sm font-mono font-bold text-zinc-100">{modelResult.filename}</span>
              </div>
              <p className="text-xs font-mono text-zinc-400 break-all">
                SHA-256: {modelResult.sha256}
              </p>
            </div>

            <div className="flex items-center gap-4">
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-right">
                <span className="text-[10px] text-zinc-400 uppercase font-mono block">Model Risk Score</span>
                <span
                  className={`font-mono text-2xl font-bold ${
                    modelResult.modelRisk > 50
                      ? 'text-rose-400'
                      : modelResult.modelRisk > 20
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {modelResult.modelRisk}/100
                </span>
              </div>
            </div>
          </div>

          {/* Model Architecture & Specs */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
              <span className="text-zinc-400 text-xs block">Framework</span>
              <span className="text-sm font-bold text-zinc-100">{modelResult.framework}</span>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
              <span className="text-zinc-400 text-xs block">Architecture</span>
              <span className="text-sm font-bold text-zinc-100 truncate block">
                {modelResult.architecture}
              </span>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
              <span className="text-zinc-400 text-xs block">Estimated Parameters</span>
              <span className="text-sm font-bold text-zinc-200">
                {modelResult.parameterCount ? modelResult.parameterCount.toLocaleString() : 'N/A'}
              </span>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
              <span className="text-zinc-400 text-xs block">Assurance Confidence</span>
              <span className="text-sm font-bold text-emerald-400">
                {(modelResult.confidence * 100).toFixed(0)}%
              </span>
            </div>
          </div>

          {/* Behavioral & Backdoor Scan Section */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-2.5">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <FileCode className="h-4 w-4 text-emerald-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Behavioral &amp; Graph Topology Evaluation
                </h3>
              </div>
              <p className="text-xs text-zinc-300 leading-relaxed font-sans">
                {modelResult.behavioralAnalysis}
              </p>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-2.5">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <ShieldAlert className="h-4 w-4 text-amber-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Backdoor &amp; Trojan Trigger Analysis
                </h3>
              </div>
              <p className="text-xs text-zinc-300 leading-relaxed font-sans">
                {modelResult.backdoorAnalysis}
              </p>
            </div>
          </div>

          {/* Forensic Evidence & Limitations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Limitations Disclosure */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-2.5">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <Info className="h-4 w-4 text-cyan-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Analysis Boundaries &amp; Non-Detection Guarantees
                </h3>
              </div>
              <p className="text-xs text-zinc-400 leading-relaxed font-mono">
                {modelResult.limitations}
              </p>
            </div>

            {/* Empirical Evidence */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-2.5">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <Cpu className="h-4 w-4 text-purple-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  Static Analysis Evidence Payload
                </h3>
              </div>
              <pre className="rounded bg-zinc-950 p-2.5 text-[11px] font-mono text-zinc-300 overflow-x-auto">
                {JSON.stringify(modelResult.evidence, null, 2)}
              </pre>
            </div>
          </div>

          {/* Findings List */}
          {modelResult.findings && modelResult.findings.length > 0 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-rose-400" />
                  <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                    Security Findings ({modelResult.findings.length})
                  </h3>
                </div>
              </div>

              <div className="divide-y divide-zinc-800">
                {modelResult.findings.map(f => (
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
