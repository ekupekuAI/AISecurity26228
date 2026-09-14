import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Code,
  X,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  Link,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Printer,
  Lock,
  RefreshCw,
} from 'lucide-react';
import {
  listAnalyses,
  getAnalysisById,
  fetchAuditEvents,
  verifyAuditChain,
  fetchGovernanceReport,
} from '../../api/client.js';
import { AssuranceReport, AuditEvent } from '../../types.js';
import { StatusBadge } from '../StatusBadge.js';

export const HistoryPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'ANALYSES' | 'AUDIT_CHAIN' | 'GOVERNANCE_REPORT'>('ANALYSES');
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [governanceReport, setGovernanceReport] = useState<AssuranceReport | null>(null);
  const [chainStatus, setChainStatus] = useState<{
    valid: boolean;
    chainLength: number;
    genesisHash: string;
    headHash: string;
    tamperedEventId?: string;
    details: string;
  } | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [isVerifyingChain, setIsVerifyingChain] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [inspectRecord, setInspectRecord] = useState<any | null>(null);
  const [isCopied, setIsCopied] = useState(false);

  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    setIsLoading(true);
    try {
      const [analysesData, auditData, reportData, verification] = await Promise.all([
        listAnalyses().catch(() => []),
        fetchAuditEvents().catch(() => []),
        fetchGovernanceReport().catch(() => null),
        verifyAuditChain().catch(() => null),
      ]);
      setAnalyses(analysesData);
      setAuditEvents(auditData);
      setGovernanceReport(reportData);
      setChainStatus(verification);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyChain = async () => {
    setIsVerifyingChain(true);
    try {
      const status = await verifyAuditChain();
      setChainStatus(status);
      const updatedAudit = await fetchAuditEvents();
      setAuditEvents(updatedAudit);
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setIsVerifyingChain(false);
    }
  };

  const handleInspect = async (id: string) => {
    try {
      const full = await getAnalysisById(id);
      setInspectRecord(full);
    } catch (err) {
      alert((err as Error).message);
    }
  };

  const handleCopyJson = () => {
    if (!inspectRecord) return;
    navigator.clipboard.writeText(JSON.stringify(inspectRecord, null, 2));
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  const filtered = analyses.filter((a) => {
    const matchesSearch =
      a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.sha256.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = typeFilter === 'ALL' || a.type === typeFilter;
    const matchesStatus = statusFilter === 'ALL' || a.status === statusFilter;
    return matchesSearch && matchesType && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-zinc-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <History className="h-5 w-5 text-emerald-400" />
            <h2 className="text-lg font-bold text-zinc-100">Audit Trail, Cryptographic Ledger &amp; Assurance Reports</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Tamper-evident append-only SHA-256 hash-chained ledger and defense-grade assurance certifications.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadAllData}
            className="rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-mono text-zinc-200 hover:bg-zinc-700 transition flex items-center gap-1.5"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh Data
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-zinc-800 pb-2 text-xs font-mono">
        <button
          onClick={() => setActiveTab('ANALYSES')}
          className={`px-3.5 py-1.5 rounded-lg transition flex items-center gap-1.5 ${
            activeTab === 'ANALYSES'
              ? 'bg-zinc-800 text-emerald-400 font-semibold border border-zinc-700'
              : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <History className="h-3.5 w-3.5" />
          Pipeline Analyses ({analyses.length})
        </button>

        <button
          onClick={() => setActiveTab('AUDIT_CHAIN')}
          className={`px-3.5 py-1.5 rounded-lg transition flex items-center gap-1.5 ${
            activeTab === 'AUDIT_CHAIN'
              ? 'bg-zinc-800 text-emerald-400 font-semibold border border-zinc-700'
              : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Link className="h-3.5 w-3.5" />
          Cryptographic Hash Chain ({auditEvents.length} Blocks)
        </button>

        <button
          onClick={() => setActiveTab('GOVERNANCE_REPORT')}
          className={`px-3.5 py-1.5 rounded-lg transition flex items-center gap-1.5 ${
            activeTab === 'GOVERNANCE_REPORT'
              ? 'bg-zinc-800 text-emerald-400 font-semibold border border-zinc-700'
              : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <FileText className="h-3.5 w-3.5" />
          Formal Assurance Report &amp; Decision Triad
        </button>
      </div>

      {/* TAB 1: Analyses Table */}
      {activeTab === 'ANALYSES' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs font-mono">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
              <input
                type="text"
                placeholder="Search by asset name, ID, or SHA-256 hash..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950 pl-9 pr-3 py-2 text-zinc-200 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <span className="text-zinc-500">Type:</span>
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-zinc-300 focus:outline-none"
                >
                  <option value="ALL">All Types</option>
                  <option value="DATASET">Dataset</option>
                  <option value="MODEL">Model</option>
                  <option value="INFERENCE">Inference</option>
                  <option value="DISTRIBUTION">Distribution</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-zinc-500">Status:</span>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-zinc-300 focus:outline-none"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="DETECTED">Detected</option>
                  <option value="SUSPICIOUS">Suspicious</option>
                  <option value="NOT DETECTED">Not Detected</option>
                  <option value="NOT SUPPORTED">Not Supported</option>
                  <option value="ANALYSIS FAILED">Failed</option>
                </select>
              </div>
            </div>
          </div>

          {/* Analyses Table */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="border-b border-zinc-800 bg-zinc-950/60 text-zinc-400 uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Asset Name</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">SHA-256 Hash</th>
                    <th className="py-3 px-4">Assurance Status</th>
                    <th className="py-3 px-4 text-right">Risk Score</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 text-zinc-300">
                  {isLoading ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-zinc-500">
                        Loading records from SQLite...
                      </td>
                    </tr>
                  ) : filtered.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-zinc-500">
                        No matching pipeline analyses found.
                      </td>
                    </tr>
                  ) : (
                    filtered.map((a) => (
                      <tr key={a.id} className="hover:bg-zinc-800/30 transition">
                        <td className="py-3 px-4 font-sans font-medium text-zinc-200">
                          <div className="flex items-center gap-2">
                            <span>{a.name}</span>
                            {a.isDemo && (
                              <span className="text-[10px] rounded bg-zinc-800 text-amber-400 border border-zinc-700 px-1 font-mono">
                                DEMO
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-zinc-400">{a.type}</td>
                        <td className="py-3 px-4 text-zinc-500 truncate max-w-[150px]">{a.sha256}</td>
                        <td className="py-3 px-4">
                          <StatusBadge status={a.status} size="sm" />
                        </td>
                        <td className="py-3 px-4 text-right font-bold">
                          <span
                            className={
                              a.risk > 50 ? 'text-rose-400' : a.risk > 20 ? 'text-amber-400' : 'text-emerald-400'
                            }
                          >
                            {a.risk}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-zinc-500">
                          {new Date(a.timestamp).toLocaleString(undefined, {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => handleInspect(a.id)}
                            className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-2.5 py-1 text-[11px] transition inline-flex items-center gap-1"
                          >
                            <Code className="h-3 w-3" /> JSON Payload
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Cryptographic Audit Chain */}
      {activeTab === 'AUDIT_CHAIN' && (
        <div className="space-y-6">
          {/* Chain Integrity Summary Card */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Lock className="h-4 w-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-zinc-100 font-mono">
                    Append-Only SHA-256 Cryptographic Hash Chain Ledger
                  </h3>
                </div>
                <p className="text-xs text-zinc-400">
                  Each audit block cryptographically binds to its predecessor: <br />
                  <code className="text-zinc-300 bg-zinc-950 px-1.5 py-0.5 rounded border border-zinc-800">
                    current_hash = SHA-256(previous_hash : id : eventType : assetHash : timestamp : description)
                  </code>
                </p>
              </div>

              <button
                onClick={handleVerifyChain}
                disabled={isVerifyingChain}
                className="rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 text-xs font-semibold shadow transition disabled:opacity-50 flex items-center gap-2 shrink-0 font-mono"
              >
                {isVerifyingChain ? (
                  <>
                    <span className="h-3 w-3 animate-spin rounded-full border border-white border-t-transparent" />
                    Verifying Chain...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-4 w-4" /> Run Full Chain Verification
                  </>
                )}
              </button>
            </div>

            {/* Verification Result Banner */}
            {chainStatus && (
              <div
                className={`mt-4 rounded-lg p-4 border flex items-start gap-3 text-xs font-mono ${
                  chainStatus.valid
                    ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-200'
                    : 'bg-rose-950/30 border-rose-800/80 text-rose-200'
                }`}
              >
                {chainStatus.valid ? (
                  <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
                )}
                <div className="space-y-1">
                  <div className="font-bold uppercase">
                    {chainStatus.valid
                      ? 'CRYPTOGRAPHIC INTEGRITY VERIFIED (0 DISCREPANCIES)'
                      : 'TAMPER DETECTED: AUDIT CHAIN HASH MISMATCH'}
                  </div>
                  <p className="text-zinc-300">{chainStatus.details}</p>
                  <div className="text-[11px] text-zinc-400 flex flex-wrap gap-4 pt-1">
                    <span>
                      Genesis Hash:{' '}
                      <strong className="text-zinc-200">{chainStatus.genesisHash?.slice(0, 16)}...</strong>
                    </span>
                    <span>
                      Head Hash:{' '}
                      <strong className="text-zinc-200">{chainStatus.headHash?.slice(0, 16)}...</strong>
                    </span>
                    <span>
                      Total Blocks: <strong className="text-zinc-200">{chainStatus.chainLength}</strong>
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Chain Blocks Timeline */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono font-semibold text-zinc-400 uppercase tracking-wider">
              Chronological Hash Ledger Blocks ({auditEvents.length})
            </h4>

            <div className="space-y-3">
              {auditEvents.map((evt, idx) => (
                <div
                  key={evt.id}
                  className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-2.5 font-mono text-xs hover:border-zinc-700 transition"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800/80 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-zinc-800 text-zinc-300 px-2 py-0.5 text-[11px] font-bold">
                        Block #{auditEvents.length - idx}
                      </span>
                      <span className="text-emerald-400 font-bold">{evt.eventType}</span>
                      <span
                        className={`text-[10px] rounded px-1.5 py-0.2 border ${
                          evt.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-400 border-rose-800'
                            : evt.severity === 'HIGH'
                            ? 'bg-orange-950 text-orange-400 border-orange-800'
                            : evt.severity === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-400 border-amber-800'
                            : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                        }`}
                      >
                        {evt.severity}
                      </span>
                    </div>
                    <span className="text-zinc-500 text-[11px]">
                      {new Date(evt.timestamp).toLocaleString()}
                    </span>
                  </div>

                  <p className="text-zinc-200 text-xs font-sans leading-relaxed">{evt.description}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-2 border-t border-zinc-800/60 text-[11px]">
                    <div>
                      <span className="text-zinc-500 block">Previous Block Hash (Parent Link):</span>
                      <span className="text-zinc-400 break-all">{evt.previousHash || '0000000000000000000000000000000000000000000000000000000000000000'}</span>
                    </div>
                    <div>
                      <span className="text-emerald-500/80 block">Current Block Hash:</span>
                      <span className="text-emerald-400 break-all font-semibold">{evt.currentHash || 'Pending'}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Formal Assurance Report & Governance Decision */}
      {activeTab === 'GOVERNANCE_REPORT' && governanceReport && (
        <div className="space-y-6">
          {/* Printable Report Container */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 md:p-8 space-y-6 shadow-2xl">
            {/* Classified Document Header */}
            <div className="border-b-2 border-zinc-700 pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="inline-flex items-center gap-2 rounded bg-rose-950 text-rose-300 border border-rose-800 px-2.5 py-0.5 text-xs font-mono uppercase font-bold tracking-widest">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  {governanceReport.classification}
                </div>
                <h1 className="text-xl md:text-2xl font-bold text-zinc-100 font-mono tracking-tight mt-2">
                  AI PIPELINE ASSURANCE &amp; GOVERNANCE REPORT
                </h1>
                <p className="text-xs text-zinc-400 font-mono mt-0.5">
                  Deployment Target: <strong>{governanceReport.deployment}</strong> | Problem Statement: <strong>{governanceReport.problemStatementId}</strong>
                </p>
              </div>

              <div className="text-right font-mono text-xs text-zinc-400">
                <div>Report ID: <strong className="text-zinc-200">{governanceReport.reportId}</strong></div>
                <div>Generated: {new Date(governanceReport.generatedAt).toUTCString()}</div>
              </div>
            </div>

            {/* Decision Triad Hero Banner */}
            <div
              className={`rounded-xl p-6 border flex flex-col md:flex-row md:items-center justify-between gap-6 ${
                governanceReport.decision === 'QUARANTINE'
                  ? 'bg-rose-950/40 border-rose-800 text-rose-100'
                  : governanceReport.decision === 'REVIEW'
                  ? 'bg-amber-950/40 border-amber-800 text-amber-100'
                  : 'bg-emerald-950/40 border-emerald-800 text-emerald-100'
              }`}
            >
              <div className="space-y-2">
                <span className="text-xs font-mono uppercase tracking-widest text-zinc-400 block">
                  Mandated Governance Disposition (PRD Page 8 Triad):
                </span>
                <div className="flex items-center gap-3">
                  <span
                    className={`text-2xl md:text-3xl font-black font-mono tracking-wider px-4 py-1 rounded-lg border shadow-inner ${
                      governanceReport.decision === 'QUARANTINE'
                        ? 'bg-rose-900/80 border-rose-700 text-rose-200'
                        : governanceReport.decision === 'REVIEW'
                        ? 'bg-amber-900/80 border-amber-700 text-amber-200'
                        : 'bg-emerald-900/80 border-emerald-700 text-emerald-200'
                    }`}
                  >
                    {governanceReport.decision}
                  </span>
                  <div className="text-xs font-mono">
                    <div>Overall Pipeline Risk: <strong className="text-base">{governanceReport.overallRisk}%</strong></div>
                    <div>Inference Integrity: <strong>{governanceReport.inferenceIntegrityStatus}</strong></div>
                  </div>
                </div>
                <p className="text-xs font-mono font-semibold pt-1 text-zinc-200">
                  {governanceReport.actionRequired}
                </p>
              </div>

              {/* Seal Stamp */}
              <div className="rounded-lg border border-zinc-700 bg-zinc-950/80 p-3 shrink-0 text-center font-mono text-[11px] space-y-1">
                <div className="text-zinc-500 uppercase tracking-wider">Cryptographic Seal</div>
                <div className="text-emerald-400 font-bold truncate max-w-[200px]">
                  {governanceReport.cryptographicSeal.slice(0, 24)}...
                </div>
                <div className="text-[10px] text-zinc-500">HMAC-SHA256 DEFENSE ROOT</div>
              </div>
            </div>

            {/* Risk Breakdown Across 4 Assurance Pillars */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
                <span className="text-zinc-500 text-[11px] block">Dataset Risk (35%):</span>
                <span className={`text-lg font-bold ${governanceReport.datasetRisk > 50 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {governanceReport.datasetRisk}%
                </span>
                <span className="text-[10px] text-zinc-500 block truncate">{governanceReport.datasetAssetId}</span>
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
                <span className="text-zinc-500 text-[11px] block">Model Risk (35%):</span>
                <span className={`text-lg font-bold ${governanceReport.modelRisk > 50 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {governanceReport.modelRisk}%
                </span>
                <span className="text-[10px] text-zinc-500 block truncate">{governanceReport.modelAssetId}</span>
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
                <span className="text-zinc-500 text-[11px] block">Covariate Shift (15%):</span>
                <span className={`text-lg font-bold ${governanceReport.distributionShiftRisk > 50 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {governanceReport.distributionShiftRisk}%
                </span>
                <span className="text-[10px] text-zinc-500 block">MMD &amp; KS Battery</span>
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
                <span className="text-zinc-500 text-[11px] block">Inference (15%):</span>
                <span className={`text-lg font-bold ${governanceReport.inferenceIntegrityStatus === 'TAMPERED' ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {governanceReport.inferenceIntegrityStatus}
                </span>
                <span className="text-[10px] text-zinc-500 block">SHA-256 Provenance</span>
              </div>
            </div>

            {/* Findings & Evidence Breakdown */}
            <div className="space-y-4 pt-2">
              <h4 className="text-xs font-mono font-semibold text-zinc-300 uppercase tracking-wider border-b border-zinc-800 pb-2">
                Forensic Defect Manifest
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-4 space-y-2">
                  <span className="text-amber-400 font-bold block">Dataset Findings:</span>
                  <ul className="space-y-1.5 text-zinc-300">
                    {governanceReport.breakdown.datasetNotes.map((note, i) => (
                      <li key={i} className="flex items-start gap-1.5 text-[11px]">
                        <span className="text-rose-400 font-bold">•</span>
                        <span>{note}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-4 space-y-2">
                  <span className="text-rose-400 font-bold block">Model Topology &amp; Weights:</span>
                  <ul className="space-y-1.5 text-zinc-300">
                    {governanceReport.breakdown.modelNotes.map((note, i) => (
                      <li key={i} className="flex items-start gap-1.5 text-[11px]">
                        <span className="text-rose-400 font-bold">•</span>
                        <span>{note}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="border-t border-zinc-800 pt-4 flex items-center justify-between">
              <span className="text-xs font-mono text-zinc-500">
                Non-repudiation certified by Defense Geographic Information System (DGIS)
              </span>

              <button
                onClick={() => window.print()}
                className="rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 px-4 py-2 text-xs font-mono font-semibold transition flex items-center gap-2"
              >
                <Printer className="h-3.5 w-3.5" /> Print / Export Assurance Certification
              </button>
            </div>
          </div>
        </div>
      )}

      {/* JSON Payload Inspector Modal */}
      {inspectRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs">
          <div className="relative w-full max-w-3xl rounded-xl border border-zinc-800 bg-zinc-950 p-5 shadow-2xl flex flex-col max-h-[85vh]">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
              <div className="flex items-center gap-2 font-mono text-xs text-zinc-300">
                <Code className="h-4 w-4 text-emerald-400" />
                <span className="font-bold">
                  {inspectRecord.filename || inspectRecord.name || inspectRecord.id}
                </span>
                {inspectRecord.isDemo && (
                  <span className="rounded bg-zinc-800 text-amber-400 border border-zinc-700 px-1 text-[10px]">
                    DEMO
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyJson}
                  className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-2.5 py-1 text-xs font-mono transition flex items-center gap-1"
                >
                  {isCopied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  {isCopied ? 'Copied' : 'Copy'}
                </button>
                <button
                  onClick={() => setInspectRecord(null)}
                  className="rounded p-1 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            <div className="mt-3 flex-1 overflow-auto rounded-lg border border-zinc-800 bg-zinc-900/70 p-4">
              <pre className="text-xs font-mono text-zinc-300 leading-relaxed">
                {JSON.stringify(inspectRecord, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

