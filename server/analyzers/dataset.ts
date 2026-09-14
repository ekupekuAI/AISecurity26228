/**
 * Dataset Integrity Analyzer (Node.js)
 * Real forensic inspection of computer vision training archives and images
 */

import crypto from 'node:crypto';
import path from 'node:path';
import AdmZip from 'adm-zip';
import {
  AnomalousSample,
  AssuranceStatus,
  DatasetAnalysisResult,
  DuplicateGroup,
  Finding,
  NearDuplicatePair,
} from '../../src/types.js';
import { DeterministicRiskEngine } from './risk_engine.js';

const IMAGE_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.webp', '.bmp', '.gif', '.tiff']);

function isValidImageMagicBytes(buffer: Buffer, ext: string): boolean {
  if (buffer.length < 12) return false;
  if (ext === '.jpg' || ext === '.jpeg') {
    return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  }
  if (ext === '.png') {
    return (
      buffer[0] === 0x89 &&
      buffer[1] === 0x50 &&
      buffer[2] === 0x4e &&
      buffer[3] === 0x47 &&
      buffer[4] === 0x0d &&
      buffer[5] === 0x0a &&
      buffer[6] === 0x1a &&
      buffer[7] === 0x0a
    );
  }
  if (ext === '.gif') {
    const header = buffer.subarray(0, 6).toString('ascii');
    return header === 'GIF87a' || header === 'GIF89a';
  }
  if (ext === '.bmp') {
    return buffer[0] === 0x42 && buffer[1] === 0x4d;
  }
  if (ext === '.webp') {
    return (
      buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
      buffer.subarray(8, 12).toString('ascii') === 'WEBP'
    );
  }
  return true;
}

export class DatasetAnalyzer {
  public static calculateSha256(data: Buffer): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  public static analyze(filename: string, buffer: Buffer): DatasetAnalysisResult {
    const datasetHash = this.calculateSha256(buffer);
    const ext = path.extname(filename).toLowerCase();
    const findings: Finding[] = [];
    const now = new Date().toISOString();

    let totalSamples = 0;
    const corruptedFiles: string[] = [];
    const hashToFiles = new Map<string, string[]>();
    const fileSizes = new Map<string, number>();
    const classDistribution: Record<string, number> = {};
    const contributorStats: Record<string, number> = {};

    if (ext === '.zip') {
      try {
        const zip = new AdmZip(buffer);
        const zipEntries = zip.getEntries();

        for (const entry of zipEntries) {
          if (entry.isDirectory) continue;

          const entryName = entry.entryName;

          // Path traversal safeguard (Zip Slip attack mitigation)
          if (entryName.includes('..') || entryName.startsWith('/') || entryName.startsWith('\\')) {
            findings.push({
              id: `FIND-ZIP-SLIP-${findings.length + 1}`,
              findingId: 'SEC-PATH-TRAVERSAL-ZIP',
              category: 'DATASET',
              severity: 'CRITICAL',
              confidence: 1.0,
              affectedAsset: entryName,
              explanation: 'Malicious directory traversal characters detected in zip entry filename.',
              evidence: `Entry filename: ${entryName}`,
              recommendation: 'Quarantine archive immediately. Prevent automatic decompression.',
              timestamp: now,
            });
            continue;
          }

          const fileExt = path.extname(entryName).toLowerCase();
          if (IMAGE_EXTENSIONS.has(fileExt)) {
            totalSamples++;
            const fileData = entry.getData();
            fileSizes.set(entryName, fileData.length);

            // Magic byte validation
            if (!isValidImageMagicBytes(fileData, fileExt)) {
              corruptedFiles.push(entryName);
              continue;
            }

            // Real SHA-256 calculation for exact duplicates
            const sampleHash = this.calculateSha256(fileData);
            const existing = hashToFiles.get(sampleHash) || [];
            existing.push(entryName);
            hashToFiles.set(sampleHash, existing);

            // Infer class from directory name (e.g. train/pedestrians/001.jpg)
            const parts = entryName.split(/[/\\]/);
            if (parts.length >= 2) {
              const inferred = parts[parts.length - 2];
              classDistribution[inferred] = (classDistribution[inferred] || 0) + 1;
            } else {
              classDistribution['unlabeled'] = (classDistribution['unlabeled'] || 0) + 1;
            }
          } else if (fileExt === '.csv' || fileExt === '.txt') {
            try {
              const text = entry.getData().toString('utf8');
              const lines = text.split(/\r?\n/).slice(0, 50);
              for (const line of lines) {
                if (line.toLowerCase().includes('user') || line.toLowerCase().includes('source')) {
                  const cols = line.split(',');
                  if (cols.length > 1) {
                    const author = cols[1].trim();
                    contributorStats[author] = (contributorStats[author] || 0) + 1;
                  }
                }
              }
            } catch {
              // Ignore non-critical metadata parse errors
            }
          }
        }
      } catch (err) {
        return {
          id: `DS-${Date.now()}`,
          filename,
          sha256: datasetHash,
          fileSizeBytes: buffer.length,
          totalSamples: 0,
          corruptedFiles: 1,
          duplicateFiles: [],
          nearDuplicateCandidates: [],
          classDistribution: {},
          suspiciousLabelPatterns: ['Corrupted or unreadable zip archive.'],
          anomalousSamples: [],
          oodIndicators: [],
          contributorStats: {},
          datasetRisk: 100.0,
          status: 'ANALYSIS FAILED',
          findings: [
            {
              id: 'FIND-CORR-ARCHIVE',
              findingId: 'DS-ARCHIVE-UNREADABLE',
              category: 'DATASET',
              severity: 'CRITICAL',
              confidence: 1.0,
              affectedAsset: filename,
              explanation: `Failed to decompress archive: ${(err as Error).message}`,
              evidence: `File size: ${buffer.length} bytes`,
              recommendation: 'Re-export archive and re-verify file integrity.',
              timestamp: now,
            },
          ],
          timestamp: now,
        };
      }
    } else {
      // Single loose image
      totalSamples = 1;
      fileSizes.set(filename, buffer.length);
      if (!isValidImageMagicBytes(buffer, ext)) {
        corruptedFiles.push(filename);
      } else {
        hashToFiles.set(datasetHash, [filename]);
        classDistribution['default'] = 1;
      }
    }

    // Build duplicate groups
    const duplicateGroups: DuplicateGroup[] = [];
    for (const [shash, files] of hashToFiles.entries()) {
      if (files.length > 1) {
        duplicateGroups.push({
          hash: shash,
          filenames: files,
          sampleCount: files.length,
        });

        findings.push({
          id: `FIND-DUP-${findings.length + 1}`,
          findingId: `DS-EXACT-DUP-${shash.substring(0, 8)}`,
          category: 'DATASET',
          severity: 'MEDIUM',
          confidence: 1.0,
          affectedAsset: files.slice(0, 3).join(', '),
          explanation: `Exact bit-for-bit duplicate detected across ${files.length} instances.`,
          evidence: `SHA-256 match: ${shash}`,
          recommendation: 'Deduplicate dataset to avoid model memorization and test leakage.',
          timestamp: now,
        });
      }
    }

    // Identify near-duplicate candidates via byte size variance (<1.5%)
    const nearDuplicateCandidates: NearDuplicatePair[] = [];
    const sizeEntries = Array.from(fileSizes.entries());
    for (let i = 0; i < sizeEntries.length; i++) {
      for (let j = i + 1; j < Math.min(i + 15, sizeEntries.length); j++) {
        const [fn1, s1] = sizeEntries[i];
        const [fn2, s2] = sizeEntries[j];
        if (s1 > 0 && s2 > 0 && fn1 !== fn2) {
          const diffPct = Math.abs(s1 - s2) / Math.max(s1, s2);
          if (diffPct < 0.015) {
            nearDuplicateCandidates.push({
              sampleA: fn1,
              sampleB: fn2,
              similarity: Math.round((1.0 - diffPct) * 10000) / 10000,
              metrics: `Byte length variance: ${(diffPct * 100).toFixed(2)}%`,
            });
          }
        }
      }
    }

    // Corrupted files findings
    if (corruptedFiles.length > 0) {
      findings.push({
        id: `FIND-CORR-${findings.length + 1}`,
        findingId: 'DS-CORRUPT-HEADER',
        category: 'DATASET',
        severity: 'HIGH',
        confidence: 0.98,
        affectedAsset: `${corruptedFiles.length} samples`,
        explanation: `${corruptedFiles.length} image files have damaged header signatures or truncated byte payloads.`,
        evidence: `Sample corrupt paths: ${corruptedFiles.slice(0, 3).join(', ')}`,
        recommendation: 'Purge corrupt samples to prevent pipeline ingestion crashes.',
        timestamp: now,
      });
    }

    // Class imbalance & label patterns
    const suspiciousLabelPatterns: string[] = [];
    let imbalanceRatio = 1.0;
    const classCounts = Object.values(classDistribution);
    if (classCounts.length > 1) {
      const maxCount = Math.max(...classCounts);
      const minCount = Math.max(1, Math.min(...classCounts));
      imbalanceRatio = maxCount / minCount;

      if (imbalanceRatio > 8.0) {
        const patternMsg = `Substantial class skew detected: ${imbalanceRatio.toFixed(1)}:1 ratio between dominant and minority classes.`;
        suspiciousLabelPatterns.push(patternMsg);
        findings.push({
          id: `FIND-IMBAL-${findings.length + 1}`,
          findingId: 'DS-CLASS-IMBALANCE',
          category: 'DATASET',
          severity: 'MEDIUM',
          confidence: 0.9,
          affectedAsset: 'Dataset Class Labels',
          explanation: patternMsg,
          evidence: `Distribution map: ${JSON.stringify(classDistribution)}`,
          recommendation: 'Perform focal loss re-weighting or stratified data augmentation.',
          timestamp: now,
        });
      }
    }

    // Anomalous / OOD sample detection (stdev analysis)
    const anomalousSamples: AnomalousSample[] = [];
    const oodIndicators: string[] = [];
    if (sizeEntries.length > 0) {
      const allSizes = sizeEntries.map(([, sz]) => sz);
      const mean = allSizes.reduce((a, b) => a + b, 0) / allSizes.length;
      const variance = allSizes.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / Math.max(1, allSizes.length);
      const stdDev = Math.sqrt(variance);

      for (const [fn, sz] of sizeEntries) {
        if (stdDev > 0 && Math.abs(sz - mean) > 2.8 * stdDev) {
          const score = Math.min(1.0, Math.round((Math.abs(sz - mean) / (stdDev * 3.0)) * 100) / 100);
          anomalousSamples.push({
            filename: fn,
            reason: `Byte payload (${sz} B) deviates significantly (>2.8 stdev) from corpus mean (${Math.round(mean)} B).`,
            anomalyScore: score,
            metric: `${sz} B vs μ=${Math.round(mean)} B, σ=${Math.round(stdDev)}`,
          });
        }
      }
    }

    if (anomalousSamples.length > 0) {
      oodIndicators.push(`${anomalousSamples.length} samples identified as distribution outliers.`);
    }

    // Status assignment
    let status: AssuranceStatus = 'NOT DETECTED';
    if (findings.some(f => f.severity === 'CRITICAL')) {
      status = 'DETECTED';
    } else if (findings.some(f => f.severity === 'HIGH' || f.severity === 'MEDIUM')) {
      status = 'SUSPICIOUS';
    }

    const findingsRisk = DeterministicRiskEngine.calculateFindingsRisk(findings);
    const datasetRisk = DeterministicRiskEngine.calculateDatasetRisk({
      totalSamples: Math.max(1, totalSamples),
      corruptedCount: corruptedFiles.length,
      duplicateCount: duplicateGroups.reduce((acc, g) => acc + g.sampleCount, 0),
      anomalousCount: anomalousSamples.length,
      classImbalanceRatio: imbalanceRatio,
      findingsRisk,
    });

    return {
      id: `DS-${Date.now()}`,
      filename,
      sha256: datasetHash,
      fileSizeBytes: buffer.length,
      totalSamples,
      corruptedFiles: corruptedFiles.length,
      duplicateFiles: duplicateGroups,
      nearDuplicateCandidates: nearDuplicateCandidates.slice(0, 20),
      classDistribution,
      suspiciousLabelPatterns,
      anomalousSamples: anomalousSamples.slice(0, 25),
      oodIndicators,
      contributorStats,
      datasetRisk,
      status,
      findings,
      timestamp: now,
    };
  }
}
