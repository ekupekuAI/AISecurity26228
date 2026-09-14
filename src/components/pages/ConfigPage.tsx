import React, { useState, useEffect } from 'react';
import {
  Settings,
  Server,
  Database,
  Cpu,
  Sparkles,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Sliders,
} from 'lucide-react';
import { SystemConfig } from '../../types.js';
import { fetchSystemConfig, updateSystemConfig, fetchHealth } from '../../api/client.js';

interface ConfigPageProps {
  onSeedDemo: () => void;
  onClearDemo: () => void;
  isActionLoading: boolean;
}

export const ConfigPage: React.FC<ConfigPageProps> = ({
  onSeedDemo,
  onClearDemo,
  isActionLoading,
}) => {
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [mlUrlInput, setMlUrlInput] = useState('http://localhost:8000');
  const [isSaving, setIsSaving] = useState(false);
  const [healthStatus, setHealthStatus] = useState<any | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    try {
      const c = await fetchSystemConfig();
      setConfig(c);
      setMlUrlInput(c.mlServiceUrl);
      const h = await fetchHealth();
      setHealthStatus(h);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    try {
      await updateSystemConfig({ mlServiceUrl: mlUrlInput });
      await loadConfig();
      alert('ML service connection target updated successfully.');
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setIsSaving(false);
    }
  };

  const testConnection = async () => {
    setIsTesting(true);
    try {
      const h = await fetchHealth();
      setHealthStatus(h);
      const c = await fetchSystemConfig();
      setConfig(c);
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-2">
          <Settings className="h-5 w-5 text-emerald-400" />
          <h2 className="text-lg font-bold text-zinc-100">System Infrastructure &amp; Security Controls</h2>
        </div>
        <p className="text-xs text-zinc-400 mt-1">
          Python ML microservice connection parameters, SQLite persistence settings, and pipeline risk weights.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Python ML Service Configuration */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-emerald-400" />
              <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
                Python FastAPI ML Engine Connection
              </h3>
            </div>
            <button
              onClick={testConnection}
              disabled={isTesting}
              className="text-[11px] font-mono text-zinc-400 hover:text-zinc-200 flex items-center gap-1"
            >
              <RefreshCw className={`h-3 w-3 ${isTesting ? 'animate-spin' : ''}`} /> Test Ping
            </button>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950 p-3">
              <span className="text-zinc-400">Status:</span>
              {config?.mlServiceStatus === 'ONLINE' ? (
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Python ML Service Online (FastAPI)
                </span>
              ) : (
                <span className="text-amber-400 font-bold flex items-center gap-1">
                  <AlertTriangle className="h-3.5 w-3.5" /> Standalone Node Engine Active
                </span>
              )}
            </div>

            <p className="text-[11px] text-zinc-400 leading-relaxed font-sans pt-1">
              When the Python service is running on port 8000, intensive ML forensic workloads are routed directly to it. If offline, the Node.js server automatically runs its built-in matching deterministic engine with zero interruption.
            </p>

            <form onSubmit={handleSaveUrl} className="pt-2 space-y-2">
              <label className="text-zinc-400 block">ML Microservice Endpoint URL</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={mlUrlInput}
                  onChange={e => setMlUrlInput(e.target.value)}
                  className="flex-1 rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-zinc-200 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={isSaving}
                  className="rounded bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 font-sans font-semibold text-xs transition disabled:opacity-50"
                >
                  {isSaving ? 'Updating...' : 'Update'}
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Database & Runtime Environment */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
            <Database className="h-4 w-4 text-purple-400" />
            <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
              Database &amp; Platform Environment
            </h3>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex justify-between items-center py-1 border-b border-zinc-800/60">
              <span className="text-zinc-400">Database Engine</span>
              <span className="text-zinc-200 font-bold">SQLite 3 (Node 22 DatabaseSync)</span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-zinc-800/60">
              <span className="text-zinc-400">Database File</span>
              <span className="text-zinc-300 truncate max-w-[240px]">
                {config?.databasePath || 'data/ai_integrity.db'}
              </span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-zinc-800/60">
              <span className="text-zinc-400">Forensic Briefing Engine</span>
              <span className="text-emerald-400 font-bold">
                Deterministic Rule-Based (Autonomous)
              </span>
            </div>
            <div className="flex justify-between items-center py-1">
              <span className="text-zinc-400">Hash Standard</span>
              <span className="text-zinc-200 font-bold">FIPS 180-4 SHA-256</span>
            </div>
          </div>
        </div>

        {/* Deterministic Risk Weight Formulation */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-3">
          <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
            <Sliders className="h-4 w-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
              Mathematical Risk Scoring Weights
            </h3>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between py-1 border-b border-zinc-800/60">
              <span className="text-zinc-400">Training Dataset Integrity (D)</span>
              <span className="text-emerald-400 font-bold">35%</span>
            </div>
            <div className="flex justify-between py-1 border-b border-zinc-800/60">
              <span className="text-zinc-400">Model Checkpoint Security (M)</span>
              <span className="text-emerald-400 font-bold">35%</span>
            </div>
            <div className="flex justify-between py-1 border-b border-zinc-800/60">
              <span className="text-zinc-400">Inference Cryptographic Provenance (I)</span>
              <span className="text-emerald-400 font-bold">15%</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-zinc-400">Covariate Distribution Shift (S)</span>
              <span className="text-emerald-400 font-bold">15%</span>
            </div>
            <div className="pt-2 text-[11px] text-zinc-500 font-sans italic">
              Overall Trust Score = 100 - (0.35·D + 0.35·M + 0.15·I + 0.15·S). Deterministic formula with zero random fluctuation.
            </div>
          </div>
        </div>

        {/* Demo Data Management */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-3">
          <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
            <Sparkles className="h-4 w-4 text-amber-400" />
            <h3 className="text-xs font-semibold text-zinc-200 uppercase font-mono">
              Demo Pipeline Corpus Management
            </h3>
          </div>

          <p className="text-xs text-zinc-400 leading-relaxed">
            Quickly seed demo training datasets and model inspection checkpoints for demonstration purposes. All seeded records are explicitly tagged with <code className="text-amber-400 font-mono">DEMO</code> and can be purged at any time without deleting your real uploads.
          </p>

          <div className="flex flex-wrap gap-2 pt-2">
            <button
              onClick={onSeedDemo}
              disabled={isActionLoading}
              className="rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 px-3 py-1.5 text-xs font-medium transition flex items-center gap-1.5 disabled:opacity-50"
            >
              <Sparkles className="h-3.5 w-3.5 text-purple-400" /> Seed Demo Pipeline Corpus
            </button>
            <button
              onClick={onClearDemo}
              disabled={isActionLoading}
              className="rounded-lg bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/60 px-3 py-1.5 text-xs font-medium transition flex items-center gap-1.5 disabled:opacity-50"
            >
              <Trash2 className="h-3.5 w-3.5 text-rose-400" /> Purge Demo Data
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
