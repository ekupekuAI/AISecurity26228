/**
 * Deterministic Risk Calculation Engine
 * Math formula for computing AI pipeline assurance & trust scores
 */

import { Finding, FindingSeverity } from '../../src/types.js';

export class DeterministicRiskEngine {
  public static readonly SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
    CRITICAL: 25.0,
    HIGH: 15.0,
    MEDIUM: 8.0,
    LOW: 3.0,
    INFO: 0.0,
  };

  public static readonly COMPONENT_WEIGHTS = {
    dataset: 0.35,
    model: 0.35,
    inference: 0.15,
    shift: 0.15,
  };

  public static calculateFindingsRisk(findings: Finding[]): number {
    if (!findings || findings.length === 0) return 0.0;

    let rawScore = 0.0;
    for (const f of findings) {
      const weight = this.SEVERITY_WEIGHTS[f.severity] || 0.0;
      const conf = typeof f.confidence === 'number' ? f.confidence : 1.0;
      rawScore += weight * conf;
    }

    // Diminishing returns formula capping at 100
    const normalized = 100.0 * (1.0 - Math.exp(-rawScore / 45.0));
    return Math.round(Math.min(100.0, Math.max(0.0, normalized)) * 10) / 10;
  }

  public static calculateDatasetRisk(params: {
    totalSamples: number;
    corruptedCount: number;
    duplicateCount: number;
    anomalousCount: number;
    classImbalanceRatio: number;
    findingsRisk: number;
  }): number {
    const { totalSamples, corruptedCount, duplicateCount, anomalousCount, classImbalanceRatio, findingsRisk } = params;
    if (totalSamples <= 0) return 100.0;

    const corruptRatio = corruptedCount / totalSamples;
    const dupRatio = duplicateCount / totalSamples;
    const anomalyRatio = anomalousCount / totalSamples;

    const baseRisk =
      corruptRatio * 40.0 +
      dupRatio * 20.0 +
      anomalyRatio * 25.0 +
      Math.min(15.0, Math.max(0.0, (classImbalanceRatio - 1.0) * 2.5));

    const combined = baseRisk * 0.5 + findingsRisk * 0.5;
    return Math.round(Math.min(100.0, Math.max(0.0, combined)) * 10) / 10;
  }

  public static calculateOverallRisk(
    datasetRisk: number,
    modelRisk: number,
    inferenceRisk: number,
    shiftRisk: number
  ) {
    const overall =
      this.COMPONENT_WEIGHTS.dataset * datasetRisk +
      this.COMPONENT_WEIGHTS.model * modelRisk +
      this.COMPONENT_WEIGHTS.inference * inferenceRisk +
      this.COMPONENT_WEIGHTS.shift * shiftRisk;

    const overallClamped = Math.round(Math.min(100.0, Math.max(0.0, overall)) * 10) / 10;
    const trustScore = Math.round(Math.max(0.0, 100.0 - overallClamped) * 10) / 10;

    return {
      overallRisk: overallClamped,
      trustScore,
      datasetRisk: Math.round(datasetRisk * 10) / 10,
      modelRisk: Math.round(modelRisk * 10) / 10,
      inferenceRisk: Math.round(inferenceRisk * 10) / 10,
      shiftRisk: Math.round(shiftRisk * 10) / 10,
    };
  }

  public static evaluateGovernanceDecision(params: {
    overallRisk: number;
    hasCriticalFindings: boolean;
    hasTamperedInference: boolean;
    datasetRisk: number;
    modelRisk: number;
    shiftRisk: number;
  }): {
    decision: 'ACCEPT' | 'REVIEW' | 'QUARANTINE';
    actionRequired: string;
    rationale: string;
  } {
    if (params.hasCriticalFindings || params.hasTamperedInference || params.overallRisk >= 50.0 || params.modelRisk >= 75.0) {
      return {
        decision: 'QUARANTINE',
        actionRequired: 'IMMEDIATE OPERATIONAL QUARANTINE: Isolate model checkpoint, revoke untrusted contributor ingestion pipeline, and alert Defense Cyber Agency.',
        rationale: params.hasTamperedInference
          ? 'Cryptographic integrity failure: inference output payload altered in transit.'
          : params.hasCriticalFindings
          ? 'Critical backdoor / poisoning vector identified in training corpus or model topology.'
          : 'Composite pipeline risk score exceeds mission-critical safety threshold (>= 50%).',
      };
    }

    if (params.overallRisk > 20.0 || params.datasetRisk > 30.0 || params.shiftRisk > 40.0) {
      return {
        decision: 'REVIEW',
        actionRequired: 'MANDATORY HUMAN-IN-THE-LOOP AUDIT: Require secondary sign-off from Lead Assurance Engineer prior to live stream deployment.',
        rationale: 'Moderate pipeline variance or label noise detected within acceptable operational tolerances.',
      };
    }

    return {
      decision: 'ACCEPT',
      actionRequired: 'AUTHORIZED FOR OPERATIONAL MISSION DEPLOYMENT: Cryptographic seals valid; zero malicious shortcuts detected.',
      rationale: 'All four assurance pillars pass deterministic threshold batteries with composite risk <= 20%.',
    };
  }
}
