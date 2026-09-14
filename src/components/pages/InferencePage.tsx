import React, { useState } from 'react';
import {
  Fingerprint,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Sparkles,
  Lock,
} from 'lucide-react';
import { InferenceRecord, InferenceVerificationResult } from '../../types.js';
import { createInferenceRecord, verifyInferenceRecord } from '../../api/client.js';
import { StatusBadge } from '../StatusBadge.js';

interface InferencePageProps {
  onRefreshStats: () => void;
}

export const InferencePage: React.FC<InferencePageProps> = ({ onRefreshStats }) => {
  // Generator form state
  const [imageHash, setImageHash] = useState(
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
  const [modelId, setModelId] = useState('yolov8-traffic-surveillance-v2');
  const [modelSha256, setModelSha256] = useState(
    '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
  );
  const [preprocessingConfig, setPreprocessingConfig] = useState(
    '{\n  "resize": [640, 640],\n  "mean": [0.485, 0.456, 0.406],\n  "std": [0.229, 0.224, 0.225]\n}'
  );
  const [prediction, setPrediction] = useState('pedestrian_in_crosswalk');
  const [confidence, setConfidence] = useState('0.965400');
  const [timestamp, setTimestamp] = useState(new Date().toISOString());
  const [nonce, setNonce] = useState(`nonce-${Date.now().toString(36)}`);

  const [isSigning, setIsSigning] = useState(false);
  const [activeRecord, setActiveRecord] = useState<InferenceRecord | null>(null);

  // Tamper lab state
  const [tamperPrediction, setTamperPrediction] = useState('');
  const [tamperConfidence, setTamperConfidence] = useState('');
  const [tamperImageHash, setTamperImageHash] = useState('');
  const [verificationResult, setVerificationResult] = useState<InferenceVerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  const handleSignInference = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSigning(true);
    try {
      const rec = await createInferenceRecord({
        inputImageHash: imageHash,
        modelIdentifier: modelId,
        modelSha256,
        preprocessingConfig,
        prediction,
        confidence: parseFloat(confidence),
        timestamp,
        nonce,
      });
      setActiveRecord(rec);
      // Reset tamper fields to match created record
      setTamperPrediction(rec.prediction);
      setTamperConfidence(rec.confidence.toFixed(6));
      setTamperImageHash(rec.inputImageHash);
      setVerificationResult(null);
      onRefreshStats();
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setIsSigning(false);
    }
  };

  const handleVerify = async () => {
    if (!activeRecord) return;
    setIsVerifying(true);
    try {
      const res = await verifyInferenceRecord({
        expectedHash: activeRecord.recordHash,
        inputImageHash: tamperImageHash,
        modelIdentifier: activeRecord.modelIdentifier,
        modelSha256: activeRecord.modelSha256,
        preprocessingConfig: activeRecord.preprocessingConfig,
        prediction: tamperPrediction,
        confidence: parseFloat(tamperConfidence),
        timestamp: activeRecord.timestamp,
        nonce: activeRecord.nonce,
      });
      setVerificationResult(res);
      onRefreshStats();
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setIsVerifying(false);
    }
  };

  const triggerTamperSimulation = (type: 'CONFIDENCE' | 'PREDICTION' | 'IMAGE' | 'PREPROC') => {
    if (!activeRecord) return;
    if (type === 'CONFIDENCE') {
      setTamperConfidence('0.999999');
    } else if (type === 'PREDICTION') {
      setTamperPrediction(activeRecord.prediction === 'STOP_SIGN' ? 'SPEED_LIMIT' : 'safe_clear_road');
    } else if (type === 'IMAGE') {
      setTamperImageHash('0000000000000000000000000000000000000000000000000000000000000000');
    }
    setVerificationResult(null);
  };

  const resetToUntampered = () => {
    if (!activeRecord) return;
    setTamperPrediction(activeRecord.prediction);
    setTamperConfidence(activeRecord.confidence.toFixed(6));
    setTamperImageHash(activeRecord.inputImageHash);
    setVerificationResult(null);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-2">
          <Fingerprint className="h-5 w-5 text-emerald-400" />
          <h2 className="text-lg font-bold text-zinc-100">Cryptographic Inference Provenance &amp; Tamper Verification</h2>
        </div>
        <p className="text-xs text-zinc-400 mt-1">
          Cryptographically binds raw visual inputs, model checkpoint hashes, preprocessing parameters, and predictions via canonical representation and SHA-256 verification.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Step 1: Sign Inference Record */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
            <Lock className="h-4 w-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
              1. Generate Signed Inference Certificate
            </h3>
          </div>

          <button
            type="button"
            onClick={() => {
              setImageHash('a81f3e76d9c824e8109bf320149acb7190d62c65bf0bcda32b57b277d9ad9f14');
              setModelId('traffic_recon_resnet18.pth');
              setModelSha256('8fa3910cb12d8a4f91002341b590e871239ab7c40912ef6530182bc9810a924b');
              setPreprocessingConfig(
                JSON.stringify(
                  {
                    input_resolution: [224, 224],
                    mean_norm: [0.485, 0.456, 0.406],
                    std_norm: [0.229, 0.224, 0.225],
                    confidence_threshold: 0.5,
                  },
                  null,
                  2
                )
              );
              setPrediction('STOP_SIGN');
              setConfidence('0.984100');
              setNonce('99382104');
              setTimestamp('2026-09-13T06:18:22Z');
            }}
            className="w-full rounded border border-emerald-800/80 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 py-1.5 px-3 text-[11px] font-mono transition flex items-center justify-center gap-1.5"
          >
            <Sparkles className="h-3.5 w-3.5 text-emerald-400" />
            Load PRD Case Study Preset (STOP_SIGN @ Checkpoint Node)
          </button>

          <form onSubmit={handleSignInference} className="space-y-3 text-xs font-mono">
            <div>
              <label className="text-zinc-400 block mb-1">Input Image Hash (SHA-256)</label>
              <input
                type="text"
                value={imageHash}
                onChange={e => setImageHash(e.target.value)}
                required
                className="w-full rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-zinc-200 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-zinc-400 block mb-1">Model Identifier</label>
                <input
                  type="text"
                  value={modelId}
                  onChange={e => setModelId(e.target.value)}
                  required
                  className="w-full rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-zinc-200 focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-zinc-400 block mb-1">Confidence Score (0-1)</label>
                <input
                  type="number"
                  step="0.000001"
                  value={confidence}
                  onChange={e => setConfidence(e.target.value)}
                  required
                  className="w-full rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-zinc-200 focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="text-zinc-400 block mb-1">Model Weights Hash (SHA-256)</label>
              <input
                type="text"
                value={modelSha256}
                onChange={e => setModelSha256(e.target.value)}
                required
                className="w-full rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-zinc-200 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-zinc-400 block mb-1">Prediction Class</label>
              <input
                type="text"
                value={prediction}
                onChange={e => setPrediction(e.target.value)}
                required
                className="w-full rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-zinc-200 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-zinc-400 block mb-1">Preprocessing Configuration (JSON)</label>
              <textarea
                rows={3}
                value={preprocessingConfig}
                onChange={e => setPreprocessingConfig(e.target.value)}
                required
                className="w-full rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-zinc-200 focus:border-emerald-500 focus:outline-none leading-tight"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-zinc-400 block mb-1">Timestamp</label>
                <input
                  type="text"
                  value={timestamp}
                  readOnly
                  className="w-full rounded border border-zinc-800 bg-zinc-950/60 px-2.5 py-1.5 text-zinc-500"
                />
              </div>
              <div>
                <label className="text-zinc-400 block mb-1">Nonce</label>
                <input
                  type="text"
                  value={nonce}
                  readOnly
                  className="w-full rounded border border-zinc-800 bg-zinc-950/60 px-2.5 py-1.5 text-zinc-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSigning}
              className="w-full mt-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white py-2 text-xs font-semibold shadow transition disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {isSigning ? (
                <>
                  <span className="h-3 w-3 animate-spin rounded-full border border-white border-t-transparent" />
                  Computing Canonical SHA-256...
                </>
              ) : (
                <>
                  <Lock className="h-3.5 w-3.5" /> Sign &amp; Commit Provenance Record
                </>
              )}
            </button>
          </form>
        </div>

        {/* Step 2: Interactive Tamper Verification Lab */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-purple-400" />
                <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                  2. Interactive Tampering Laboratory
                </h3>
              </div>
              {activeRecord && (
                <button
                  onClick={resetToUntampered}
                  className="text-[11px] font-mono text-zinc-400 hover:text-zinc-200 flex items-center gap-1"
                >
                  <RefreshCw className="h-3 w-3" /> Reset
                </button>
              )}
            </div>

            {activeRecord ? (
              <div className="space-y-4 text-xs font-mono">
                {/* Active Record Summary */}
                <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-400 text-[11px]">Certified Hash:</span>
                    <span className="text-[10px] rounded bg-emerald-950 text-emerald-300 border border-emerald-800 px-1.5">
                      COMMITTED
                    </span>
                  </div>
                  <p className="text-emerald-400 text-xs font-bold break-all">{activeRecord.recordHash}</p>
                </div>

                {/* Simulated Tampering Buttons */}
                <div className="space-y-1.5">
                  <span className="text-zinc-400 text-[11px] uppercase block">Inject Tampered Payload:</span>
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => triggerTamperSimulation('CONFIDENCE')}
                      className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-[11px] transition"
                    >
                      Tamper Confidence (0.999999)
                    </button>
                    <button
                      onClick={() => triggerTamperSimulation('PREDICTION')}
                      className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-[11px] transition"
                    >
                      Flip Prediction ({activeRecord.prediction === 'STOP_SIGN' ? 'SPEED_LIMIT' : 'safe_clear_road'})
                    </button>
                    <button
                      onClick={() => triggerTamperSimulation('IMAGE')}
                      className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 text-[11px] transition"
                    >
                      Corrupt Input Image Hash
                    </button>
                  </div>
                </div>

                {/* Tamper editable fields */}
                <div className="space-y-2.5 pt-2 border-t border-zinc-800">
                  <div>
                    <label className="text-zinc-400 block mb-0.5">Verification Prediction Field</label>
                    <input
                      type="text"
                      value={tamperPrediction}
                      onChange={e => setTamperPrediction(e.target.value)}
                      className={`w-full rounded border px-2.5 py-1.5 text-zinc-200 focus:outline-none ${
                        tamperPrediction !== activeRecord.prediction
                          ? 'border-rose-500 bg-rose-950/30'
                          : 'border-zinc-700 bg-zinc-950'
                      }`}
                    />
                  </div>

                  <div>
                    <label className="text-zinc-400 block mb-0.5">Verification Confidence Field</label>
                    <input
                      type="text"
                      value={tamperConfidence}
                      onChange={e => setTamperConfidence(e.target.value)}
                      className={`w-full rounded border px-2.5 py-1.5 text-zinc-200 focus:outline-none ${
                        tamperConfidence !== activeRecord.confidence.toFixed(6)
                          ? 'border-rose-500 bg-rose-950/30'
                          : 'border-zinc-700 bg-zinc-950'
                      }`}
                    />
                  </div>

                  <div>
                    <label className="text-zinc-400 block mb-0.5">Verification Image Hash</label>
                    <input
                      type="text"
                      value={tamperImageHash}
                      onChange={e => setTamperImageHash(e.target.value)}
                      className={`w-full rounded border px-2.5 py-1.5 text-zinc-200 focus:outline-none ${
                        tamperImageHash !== activeRecord.inputImageHash
                          ? 'border-rose-500 bg-rose-950/30'
                          : 'border-zinc-700 bg-zinc-950'
                      }`}
                    />
                  </div>
                </div>

                <button
                  onClick={handleVerify}
                  disabled={isVerifying}
                  className="w-full rounded-lg bg-purple-700 hover:bg-purple-600 text-white py-2 text-xs font-semibold shadow transition disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {isVerifying ? (
                    'Recomputing SHA-256...'
                  ) : (
                    <>
                      <ShieldCheck className="h-3.5 w-3.5" /> Execute Cryptographic Hash Verification
                    </>
                  )}
                </button>
              </div>
            ) : (
              <div className="py-16 text-center text-zinc-400 text-xs font-mono flex flex-col items-center gap-2">
                <Fingerprint className="h-8 w-8 text-zinc-600" />
                <span>Submit and sign an inference certificate on the left to test verification and tampering.</span>
              </div>
            )}
          </div>

          {/* Verification Outcome Alert */}
          {verificationResult && (
            <div
              className={`mt-4 rounded-xl border p-4 text-xs font-mono space-y-2 ${
                verificationResult.status === 'VERIFIED'
                  ? 'border-emerald-800 bg-emerald-950/40 text-emerald-200'
                  : 'border-rose-800 bg-rose-950/40 text-rose-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {verificationResult.status === 'VERIFIED' ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 text-rose-400" />
                  )}
                  <span className="font-bold uppercase tracking-wider">
                    {verificationResult.status === 'VERIFIED'
                      ? 'INFERENCE INTEGRITY VERIFIED'
                      : 'TAMPER DETECTED: RECORD INVALID'}
                  </span>
                </div>
                <StatusBadge status={verificationResult.status} size="sm" />
              </div>

              <div className="space-y-1 text-[11px] pt-1">
                <div>
                  <span className="text-zinc-400">Recomputed SHA-256: </span>
                  <span className="font-bold break-all">{verificationResult.computedHash}</span>
                </div>
                <div>
                  <span className="text-zinc-400">Expected Record SHA-256: </span>
                  <span className="font-bold break-all">{verificationResult.expectedHash}</span>
                </div>
              </div>

              {verificationResult.mismatches.length > 0 && (
                <div className="pt-2 border-t border-rose-800/60 text-rose-300 text-[11px] leading-relaxed">
                  {verificationResult.mismatches.map((m, idx) => (
                    <p key={idx}>⚠️ {m}</p>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
