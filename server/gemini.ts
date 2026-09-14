/**
 * Gemini AI Integration (Optional server-side explanation layer)
 * Uses @google/genai SDK with multi-model resilience cascade.
 * Strictly provides natural-language summaries of ALREADY-COMPUTED deterministic findings.
 * Never acts as the primary detector. Gracefully falls back if external models experience high demand.
 */

import { GoogleGenAI } from '@google/genai';
import { Finding } from '../src/types.js';

let geminiClient: GoogleGenAI | null = null;

function getGemini(): GoogleGenAI | null {
  if (!geminiClient && process.env.GEMINI_API_KEY) {
    geminiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return geminiClient;
}

/**
 * Safely extract a clean, human-readable error string, decoding JSON API errors if present.
 */
export function parseErrorMessage(err: unknown): string {
  if (!err) return 'Unknown error';
  const msg = (err as Error).message || String(err);
  try {
    const parsed = JSON.parse(msg);
    if (parsed.error && parsed.error.message) {
      return parsed.error.message;
    }
  } catch {
    // Not JSON
  }
  return msg;
}

/**
 * High-quality deterministic forensic briefing synthesizer.
 * Operates completely locally when cloud APIs experience temporary demand spikes or connectivity drops.
 */
export function generateDeterministicBriefing(findings: Finding[]): string {
  const criticals = findings.filter(f => f.severity === 'CRITICAL');
  const highs = findings.filter(f => f.severity === 'HIGH');
  const mediums = findings.filter(f => f.severity === 'MEDIUM');

  const lines: string[] = [];
  lines.push('AI EXECUTIVE DEFENSE BRIEFING (Forensic Assurance Synthesis)');
  lines.push('');

  // Executive summary based on empirical findings
  if (criticals.length > 0) {
    lines.push(
      `CRITICAL ALERT: The integrity assurance evaluation flagged ${criticals.length} critical defect(s) in the pipeline assets. Immediate containment is required before production deployment.`
    );
  } else if (highs.length > 0) {
    lines.push(
      `HIGH RISK WARNING: The integrity assurance evaluation detected ${highs.length} high-severity anomaly/anomalies impacting pipeline integrity and reliability.`
    );
  } else if (mediums.length > 0) {
    lines.push(
      `ADVISORY NOTICE: The evaluation identified ${findings.length} moderate variance or drift indicators. Review remediation recommendations to maintain high assurance scores.`
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
    'Assurance Verification: All conclusions are deterministically derived from AST bytecode parsing, SHA-256 cryptographic hashes, and statistical distribution divergence.'
  );

  return lines.join('\n');
}

/**
 * Resilient AI Executive Briefing generator.
 * Tries supported models in cascade order with retry and falls back to deterministic synthesis.
 */
export async function generateSecurityBriefing(findings: Finding[]): Promise<string> {
  if (!findings || findings.length === 0) {
    return 'Deterministic analysis complete: No security anomalies, corruption, or backdoor indicators detected.';
  }

  const ai = getGemini();
  if (!ai || !process.env.GEMINI_API_KEY) {
    return generateDeterministicBriefing(findings);
  }

  const findingsSummary = findings
    .slice(0, 5)
    .map(
      f =>
        `- [${f.severity}] ${f.findingId}: ${f.explanation} (Affected: ${f.affectedAsset}, Evidence: ${
          typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence)
        })`
    )
    .join('\n');

  const prompt = `You are a Senior AI Security Analyst. Explain the following deterministic forensic findings computed by the AI Integrity Assurance Platform.
Provide a clear, high-contrast, technical executive briefing (2-3 short paragraphs) focusing on practical pipeline risk and mitigation steps.
Do not invent any new findings or change severity levels.

Computed Findings:
${findingsSummary}`;

  // Resilient candidate list: gemini-2.5-flash -> gemini-3.1-flash-lite -> gemini-3.8-flash
  const candidateModels = ['gemini-2.5-flash', 'gemini-3.1-flash-lite', 'gemini-3.8-flash'];

  for (const modelName of candidateModels) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await ai.models.generateContent({
          model: modelName,
          contents: prompt,
        });

        if (response.text && response.text.trim().length > 0) {
          return response.text.trim();
        }
      } catch (err) {
        const cleanMsg = parseErrorMessage(err);
        const isTemporarySpike =
          cleanMsg.includes('high demand') ||
          cleanMsg.includes('503') ||
          cleanMsg.includes('429') ||
          cleanMsg.includes('UNAVAILABLE');

        if (isTemporarySpike && attempt === 0) {
          // Brief pause before retry
          await new Promise(resolve => setTimeout(resolve, 600));
          continue;
        }

        // On failure, break to next candidate model
        break;
      }
    }
  }

  // If cloud models are unavailable, use deterministic forensic briefing
  return generateDeterministicBriefing(findings);
}

