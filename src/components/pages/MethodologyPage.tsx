import React from 'react';
import { BookOpen, ShieldAlert, Cpu, Lock, Layers, CheckCircle2, AlertOctagon } from 'lucide-react';

export const MethodologyPage: React.FC = () => {
  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-2">
          <BookOpen className="h-5 w-5 text-emerald-400" />
          <h2 className="text-lg font-bold text-zinc-100">
            Architecture, Methodology &amp; Mathematical Specification
          </h2>
        </div>
        <p className="text-xs text-zinc-400 mt-1">
          Technical documentation for the AI Integrity Assurance Platform inspired by SIH 2026 problem statement SIH26228.
        </p>
      </div>

      {/* SIH Problem Statement Overview */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6 space-y-3">
        <div className="flex items-center gap-2">
          <span className="rounded bg-emerald-950 border border-emerald-800 px-2 py-0.5 text-xs font-mono font-bold text-emerald-300">
            SIH26228 SPECIFICATION
          </span>
          <h3 className="text-sm font-semibold text-zinc-100">
            Defense-Grade Computer Vision Pipeline Assurance
          </h3>
        </div>
        <p className="text-xs text-zinc-300 leading-relaxed font-sans">
          Modern computer vision systems deployed in mission-critical applications (such as autonomous navigation, defense surveillance, and industrial robotics) are vulnerable across their entire lifecycle. Threats include poisoned training corpora, stealthy Trojan backdoors embedded in neural weights, silent covariate sensor drift, and adversarial inference tampering. This platform provides an end-to-end mathematical and cryptographic assurance framework.
        </p>
      </div>

      {/* Deterministic Mathematical Formula */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-zinc-800 pb-3">
          <Layers className="h-4 w-4 text-emerald-400" />
          <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
            1. Deterministic Risk Scoring Formula
          </h3>
        </div>

        <p className="text-xs text-zinc-300 leading-relaxed">
          The platform rejects arbitrary or randomized risk scores. All scores are derived from empirical evidence through a deterministic, reproducible mathematical function.
        </p>

        {/* Math Box */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 font-mono text-xs text-emerald-400 space-y-2">
          <div className="text-zinc-400 text-[11px] uppercase">Overall Platform Trust Score Formula:</div>
          <div className="text-sm font-bold text-zinc-100">
            TrustScore = 100 - [ 0.35·(DatasetRisk) + 0.35·(ModelRisk) + 0.15·(InferenceRisk) + 0.15·(ShiftRisk) ]
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono text-zinc-300 pt-2">
          <div className="space-y-1.5 rounded-lg border border-zinc-800/80 bg-zinc-950/40 p-3">
            <span className="text-zinc-400 font-bold block">Finding Severity Weights (w_i):</span>
            <ul className="space-y-1 text-zinc-300">
              <li>• <span className="text-rose-400 font-bold">CRITICAL</span>: 25.0 points (Exploit payload, Zip Slip)</li>
              <li>• <span className="text-amber-400 font-bold">HIGH</span>: 15.0 points (Corrupt headers, major drift)</li>
              <li>• <span className="text-yellow-400 font-bold">MEDIUM</span>: 8.0 points (Exact duplicates, class skew)</li>
              <li>• <span className="text-blue-400 font-bold">LOW</span>: 3.0 points (Near-duplicates, minor warnings)</li>
              <li>• <span className="text-zinc-500 font-bold">INFO</span>: 0.0 points (Verified safe baselines)</li>
            </ul>
          </div>

          <div className="space-y-1.5 rounded-lg border border-zinc-800/80 bg-zinc-950/40 p-3">
            <span className="text-zinc-400 font-bold block">Finding Risk Normalization:</span>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              Calculated using the diminishing returns saturation formula:
            </p>
            <div className="rounded bg-zinc-900 p-2 font-mono text-xs text-zinc-200">
              R_findings = 100 · (1 - e^(-Σ(w_i · c_i) / 45))
            </div>
            <p className="text-[11px] text-zinc-500 font-sans">
              Where <code className="text-zinc-300 font-mono">c_i</code> represents detector confidence (0.0 to 1.0).
            </p>
          </div>
        </div>
      </div>

      {/* Canonical Provenance Protocol */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-zinc-800 pb-3">
          <Lock className="h-4 w-4 text-emerald-400" />
          <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
            2. Cryptographic Canonical Provenance Protocol
          </h3>
        </div>

        <p className="text-xs text-zinc-300 leading-relaxed font-sans">
          To prevent subtle inference alteration, adversarial prediction tampering, or model substitution, every inference event is cryptographically bound into a canonical representation:
        </p>

        <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-xs text-zinc-300 overflow-x-auto">
          <code>
            input_image_hash || model_identifier || model_sha256 || sorted_preprocessing_config || prediction || confidence.toFixed(6) || timestamp || nonce
          </code>
        </div>

        <p className="text-xs text-zinc-400 font-sans leading-relaxed">
          Preprocessing parameters (e.g. bounding box transforms, normalization tensors) are parsed and deterministically key-sorted before joining. A single altered bit in the confidence (e.g., flipping 0.965400 to 0.999999) completely invalidates the SHA-256 digest, triggering an immediate <span className="text-rose-400 font-mono font-bold">TAMPERED</span> alert.
        </p>
      </div>

      {/* Safe Model Loading & Anti-Code Execution Policies */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-zinc-800 pb-3">
          <Cpu className="h-4 w-4 text-emerald-400" />
          <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
            3. Safe Model Inspection &amp; Anti-Code Execution Policy
          </h3>
        </div>

        <div className="space-y-3 text-xs font-sans text-zinc-300 leading-relaxed">
          <p>
            Standard machine learning libraries rely on Python's <code className="text-amber-400 font-mono">pickle</code> module during <code className="text-amber-400 font-mono">torch.load()</code>. Pickling permits arbitrary opcode execution, enabling attackers to construct Trojan models that execute malicious shell payloads upon ingestion.
          </p>

          <div className="rounded-lg border border-rose-900/40 bg-rose-950/20 p-3 text-rose-200/90 text-xs">
            <span className="font-bold font-mono uppercase block mb-1">Strict Platform Policy:</span>
            Untrusted checkpoints are never directly unpickled. The platform uses safe static binary inspection to detect malicious opcodes (<code className="font-mono">cos\nsystem</code>, <code className="font-mono">posix</code>, <code className="font-mono">subprocess</code>) and verifies TorchScript zip container structures. If an unsupported format or legacy raw pickle is uploaded, the platform strictly reports:
            <div className="mt-1 font-mono text-[11px] text-zinc-100 bg-zinc-950 p-1.5 rounded border border-zinc-800">
              "Analysis unsupported for this model format or architecture"
            </div>
            with status <span className="font-mono font-bold text-cyan-300">NOT SUPPORTED</span> rather than fabricating a false evaluation.
          </div>
        </div>
      </div>

      {/* Attack Taxonomy */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-zinc-800 pb-3">
          <ShieldAlert className="h-4 w-4 text-amber-400" />
          <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
            4. AI Threat Taxonomy Addressed
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 space-y-1">
            <span className="font-mono font-bold text-zinc-200">Data Poisoning &amp; Duplicates</span>
            <p className="text-zinc-400 font-sans leading-relaxed">
              Detection of exact bit-for-bit duplicate copies that cause gradient skewing, label flipping skews (&gt;8:1 ratio), and zip directory traversal exploits.
            </p>
          </div>

          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 space-y-1">
            <span className="font-mono font-bold text-zinc-200">Trojan &amp; Backdoor Triggers</span>
            <p className="text-zinc-400 font-sans leading-relaxed">
              Static convolutional weight inspection for trigger shortcut weights, clean-label trigger anomalies, and serialization payload exploits.
            </p>
          </div>

          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 space-y-1">
            <span className="font-mono font-bold text-zinc-200">Covariate Distribution Shift</span>
            <p className="text-zinc-400 font-sans leading-relaxed">
              Surveillance of production visual features (luminance, contrast variance, edge density) to flag sensor degradation and weather divergence.
            </p>
          </div>

          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 space-y-1">
            <span className="font-mono font-bold text-zinc-200">Inference Spoofing</span>
            <p className="text-zinc-400 font-sans leading-relaxed">
              Cryptographic canonical hashing of inference events ensuring tamper-evident guarantees for safety-critical edge decisions.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
