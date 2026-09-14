/**
 * Deterministic Forensic Briefing & Threat Intelligence Engine
 * Provides structured, empirical security briefings from deterministic AST bytecode checks,
 * SHA-256 cryptographic hashes, and statistical distribution divergence.
 * Fully local and autonomous — requires no external APIs or cloud dependencies.
 */

import { Finding } from '../../src/types.js';

/**
 * Deterministic forensic briefing synthesizer.
 * Compiles empirical findings into structured executive security assessments.
 */
export function generateSecurityBriefing(findings: Finding[]): string {
  if (!findings || findings.length === 0) {
    return 'Forensic assessment complete: No security vulnerabilities, corruption, or backdoor indicators detected in analyzed assets.';
  }

  const criticals = findings.filter((f) => f.severity === 'CRITICAL');
  const highs = findings.filter((f) => f.severity === 'HIGH');
  const mediums = findings.filter((f) => f.severity === 'MEDIUM');

  const lines: string[] = [];
  lines.push('EXECUTIVE SECURITY BRIEFING (Forensic Assurance Synthesis)');
  lines.push('');

  // Empirical Threat Assessment
  if (criticals.length > 0) {
    lines.push(
      `CRITICAL ALERT: The integrity assurance evaluation flagged ${criticals.length} critical defect(s) in pipeline assets. Immediate containment is required before deployment.`
    );
  } else if (highs.length > 0) {
    lines.push(
      `HIGH RISK WARNING: The evaluation detected ${highs.length} high-severity anomaly/anomalies impacting system integrity and reliability.`
    );
  } else if (mediums.length > 0) {
    lines.push(
      `ADVISORY NOTICE: Identified ${findings.length} moderate variance or drift indicators. Review remediation actions to restore assurance scores.`
    );
  } else {
    lines.push(
      'INTEGRITY VERIFIED: All evaluated assets passed structural, cryptographic, and distributional baseline checks without actionable anomalies.'
    );
  }

  lines.push('');
  lines.push('Primary Threat Vectors & Empirical Findings:');

  const prioritized = [...findings]
    .sort((a, b) => {
      const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    })
    .slice(0, 5);

  for (const f of prioritized) {
    lines.push(`• [${f.severity}] ${f.findingId} (${f.category}): ${f.explanation}`);
    if (f.affectedAsset) {
      lines.push(`  Asset: ${f.affectedAsset}`);
    }
    if (f.recommendation) {
      lines.push(`  Remediation: ${f.recommendation}`);
    }
  }

  lines.push('');
  lines.push(
    'Verification Standard: Derived deterministically via AST bytecode validation, FIPS 180-4 SHA-256 cryptographic signatures, and Kolmogorov-Smirnov distribution drift testing.'
  );

  return lines.join('\n');
}
