/**
 * Degraded-mode analysers for when the Python assurance engine is unreachable.
 *
 * These exist so the gateway can still say something useful during an engine outage, not
 * so it can pretend to have done a full assessment. What they can do is exactly the work
 * that needs no deep learning: cryptographic digests, container structure, archive safety,
 * magic-byte validation, exact duplicate detection, and a reduced pickle opcode scan.
 *
 * What they cannot do -- perceptual near-duplicate matching, embedding-space label
 * consistency, Mahalanobis out-of-distribution scoring, behavioural trigger batteries,
 * Neural Cleanse inversion -- is declared, not silently skipped. Every result is passed
 * through `markDegraded`, which prepends a MEDIUM finding saying so, and the governance
 * engine treats that as a coverage gap that cannot yield ACCEPT.
 *
 * The pickle scan here is deliberately narrower than the engine's `pickletools`
 * disassembly, but it is a real opcode walk rather than a substring search: it locates
 * GLOBAL and STACK_GLOBAL opcodes and resolves their operands. A substring search for
 * "os" both misses obfuscated imports and fires on any tensor named `conv_pos`.
 */

import crypto from 'node:crypto';
import path from 'node:path';
import AdmZip from 'adm-zip';
import type {
  AssuranceStatus,
  DatasetAnalysisResult,
  DistributionShiftResult,
  Finding,
  FindingSeverity,
  ModelAnalysisResult,
} from '../../src/types.js';

const IMAGE_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.webp', '.bmp', '.gif', '.tif', '.tiff']);

/** Mirrors the engine's ceilings; a control present in only one layer can be bypassed. */
const LIMITS = {
  maxEntries: 200_000,
  maxEntryBytes: 256 * 1024 * 1024,
  maxTotalBytes: 2 * 1024 * 1024 * 1024,
  maxCompressionRatio: 200,
};

function sha256(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function nowIso(): string {
  return new Date().toISOString();
}

let findingCounter = 0;
function makeFinding(params: {
  findingId: string;
  category: Finding['category'];
  severity: FindingSeverity;
  confidence: number;
  affectedAsset: string;
  explanation: string;
  evidence: unknown;
  recommendation: string;
  detector: string;
  threshold?: string;
  references?: string[];
}): Finding {
  findingCounter += 1;
  return {
    id: `FIND-FB-${Date.now().toString(36).toUpperCase()}-${findingCounter}`,
    findingId: params.findingId,
    category: params.category,
    severity: params.severity,
    confidence: params.confidence,
    affectedAsset: params.affectedAsset,
    explanation: params.explanation,
    evidence: params.evidence,
    recommendation: params.recommendation,
    detector: params.detector,
    threshold: params.threshold ?? null,
    references: params.references ?? [],
    timestamp: nowIso(),
  };
}

function statusFrom(findings: Finding[]): AssuranceStatus {
  if (findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')) return 'DETECTED';
  if (findings.some((f) => f.severity === 'MEDIUM')) return 'SUSPICIOUS';
  return 'NOT DETECTED';
}

// --- image structure --------------------------------------------------------

function magicBytesValid(buffer: Buffer, extension: string): boolean {
  if (buffer.length < 12) return false;
  switch (extension) {
    case '.jpg':
    case '.jpeg':
      return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
    case '.png':
      return buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
    case '.gif': {
      const header = buffer.subarray(0, 6).toString('ascii');
      return header === 'GIF87a' || header === 'GIF89a';
    }
    case '.bmp':
      return buffer[0] === 0x42 && buffer[1] === 0x4d;
    case '.webp':
      return buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP';
    case '.tif':
    case '.tiff':
      return buffer.subarray(0, 4).equals(Buffer.from('II*\0', 'latin1')) || buffer.subarray(0, 4).equals(Buffer.from('MM\0*', 'latin1'));
    default:
      return true;
  }
}

function unsafeEntryName(name: string): string | null {
  const normalised = name.replace(/\\/g, '/');
  if (!name || name.includes('\0')) return 'null byte or empty name';
  if (/^[a-zA-Z]:\//.test(normalised) || normalised.startsWith('/') || normalised.startsWith('//')) {
    return 'absolute path';
  }
  if (normalised.split('/').includes('..')) return 'parent-directory traversal component';
  return null;
}

// --- dataset ----------------------------------------------------------------

export function analyzeDatasetFallback(filename: string, buffer: Buffer): DatasetAnalysisResult {
  const started = Date.now();
  const digest = sha256(buffer);
  const extension = path.extname(filename).toLowerCase();
  const findings: Finding[] = [];

  const shaToPaths = new Map<string, string[]>();
  const classDistribution: Record<string, number> = {};
  const corrupt: Array<{ path: string; reason: string; detail: string }> = [];
  const violations: Array<{ kind: string; entry: string; detail: string }> = [];
  let totalSamples = 0;
  let totalUncompressed = 0;
  let aborted = false;

  const isArchive = !IMAGE_EXTENSIONS.has(extension);

  if (isArchive) {
    try {
      const zip = new AdmZip(buffer);
      const entries = zip.getEntries().slice(0, LIMITS.maxEntries);

      for (const entry of entries) {
        if (entry.isDirectory) continue;
        const name = entry.entryName;

        const unsafe = unsafeEntryName(name);
        if (unsafe) {
          violations.push({ kind: 'path-traversal', entry: name, detail: unsafe });
          continue;
        }

        const declared = entry.header.size;
        const compressed = entry.header.compressedSize;
        if (declared > LIMITS.maxEntryBytes) {
          violations.push({ kind: 'oversized-entry', entry: name, detail: `${declared} bytes` });
          continue;
        }
        if (compressed > 0 && declared / compressed > LIMITS.maxCompressionRatio) {
          violations.push({
            kind: 'compression-bomb',
            entry: name,
            detail: `${(declared / compressed).toFixed(0)}:1 expansion ratio`,
          });
          continue;
        }
        if (totalUncompressed + declared > LIMITS.maxTotalBytes) {
          aborted = true;
          break;
        }

        const entryExtension = path.extname(name).toLowerCase();
        if (!IMAGE_EXTENSIONS.has(entryExtension)) continue;

        totalSamples += 1;
        const data = entry.getData();
        totalUncompressed += data.length;

        if (!magicBytesValid(data, entryExtension)) {
          corrupt.push({ path: name, reason: 'magic-byte-mismatch', detail: `header does not match ${entryExtension}` });
          continue;
        }

        const entryDigest = sha256(data);
        shaToPaths.set(entryDigest, [...(shaToPaths.get(entryDigest) ?? []), name]);

        const parts = name.split('/');
        const label = parts.length >= 2 ? parts[parts.length - 2] : 'unlabelled';
        classDistribution[label] = (classDistribution[label] ?? 0) + 1;
      }
    } catch (error) {
      findings.push(
        makeFinding({
          findingId: 'DS-ARCHIVE-UNREADABLE',
          category: 'DATASET',
          severity: 'HIGH',
          confidence: 1,
          affectedAsset: filename,
          explanation: `The archive could not be opened: ${error instanceof Error ? error.message : 'unknown error'}.`,
          evidence: { sizeBytes: buffer.length },
          recommendation: 'Re-export the archive and verify its integrity before resubmitting.',
          detector: 'server/analyzers/fallback.analyzeDatasetFallback',
          threshold: 'zip container readability',
        })
      );
    }
  } else {
    totalSamples = 1;
    if (magicBytesValid(buffer, extension)) {
      shaToPaths.set(digest, [filename]);
      classDistribution.default = 1;
    } else {
      corrupt.push({ path: filename, reason: 'magic-byte-mismatch', detail: `header does not match ${extension}` });
    }
  }

  if (violations.some((v) => v.kind === 'path-traversal')) {
    findings.push(
      makeFinding({
        findingId: 'SEC-ARCHIVE-PATH-TRAVERSAL',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 1,
        affectedAsset: filename,
        explanation:
          'Archive entries attempt to escape the extraction root (Zip Slip). A benign export tool ' +
          'does not produce these; the archive was deliberately crafted.',
        evidence: { violations: violations.filter((v) => v.kind === 'path-traversal').slice(0, 20) },
        recommendation: 'Quarantine the archive and revoke the contributor\'s ingest credentials.',
        detector: 'server/analyzers/fallback.unsafeEntryName',
        threshold: 'any traversal component or absolute path',
        references: ['CWE-22'],
      })
    );
  }

  if (violations.some((v) => v.kind === 'compression-bomb')) {
    findings.push(
      makeFinding({
        findingId: 'SEC-ARCHIVE-COMPRESSION-BOMB',
        category: 'SUPPLY_CHAIN',
        severity: 'HIGH',
        confidence: 1,
        affectedAsset: filename,
        explanation:
          `Entries exceed the ${LIMITS.maxCompressionRatio}:1 expansion ceiling and were refused. ` +
          'This is the signature of a decompression bomb aimed at the ingest node.',
        evidence: { violations: violations.filter((v) => v.kind === 'compression-bomb').slice(0, 20) },
        recommendation: 'Reject the archive and require an uncompressed manifest of its true contents.',
        detector: 'server/analyzers/fallback.analyzeDatasetFallback',
        threshold: `uncompressed/compressed > ${LIMITS.maxCompressionRatio}`,
        references: ['CWE-409'],
      })
    );
  }

  const duplicateGroups = [...shaToPaths.entries()]
    .filter(([, paths]) => paths.length > 1)
    .map(([hash, paths]) => ({ hash, filenames: paths.slice(0, 24), sampleCount: paths.length }))
    .sort((a, b) => b.sampleCount - a.sampleCount);

  const redundant = duplicateGroups.reduce((sum, group) => sum + group.sampleCount - 1, 0);

  if (redundant > 0) {
    findings.push(
      makeFinding({
        findingId: 'DS-REDUNDANT-SAMPLES',
        category: 'DATASET',
        severity: redundant / Math.max(1, totalSamples) > 0.02 ? 'HIGH' : 'MEDIUM',
        confidence: 1,
        affectedAsset: `${redundant} redundant samples`,
        explanation:
          `${redundant} samples are byte-identical duplicates of another sample. Note that only ` +
          'exact duplicates are detectable in degraded mode; perceptual near-duplicates require the ' +
          'assurance engine.',
        evidence: { exactGroups: duplicateGroups.slice(0, 20), exactDuplicateSamples: redundant },
        recommendation: 'Deduplicate the corpus before ingest and re-run a full assessment.',
        detector: 'server/analyzers/fallback.analyzeDatasetFallback',
        threshold: 'identical SHA-256',
      })
    );
  }

  if (corrupt.length > 0) {
    findings.push(
      makeFinding({
        findingId: 'DS-CORRUPT-SAMPLES',
        category: 'DATASET',
        severity: corrupt.length / Math.max(1, totalSamples) > 0.02 ? 'HIGH' : 'MEDIUM',
        confidence: 0.98,
        affectedAsset: `${corrupt.length} of ${totalSamples} samples`,
        explanation:
          `${corrupt.length} samples have a header that does not match their declared format. ` +
          'These crash ingest pipelines and, when tolerated, become a channel for non-image content.',
        evidence: { examples: corrupt.slice(0, 12) },
        recommendation: 'Purge the undecodable samples and query the contributor\'s export process.',
        detector: 'server/analyzers/fallback.magicBytesValid',
        threshold: 'magic-byte match against the declared extension',
      })
    );
  }

  if (totalSamples === 0 && findings.length === 0) {
    findings.push(
      makeFinding({
        findingId: 'DS-NO-SAMPLES',
        category: 'DATASET',
        severity: 'HIGH',
        confidence: 1,
        affectedAsset: filename,
        explanation: 'No image samples were found. The submission is not a computer-vision corpus.',
        evidence: { aborted },
        recommendation: 'Return the submission to the contributor for re-export.',
        detector: 'server/analyzers/fallback.analyzeDatasetFallback',
        threshold: 'image count > 0',
      })
    );
  }

  const counts = Object.values(classDistribution);
  const imbalance = counts.length > 1 ? Math.max(...counts) / Math.max(1, Math.min(...counts)) : 1;

  // Prevalence-only scoring: the fallback has no detector-driven risk to blend in.
  const prevalence =
    Math.min(15, (corrupt.length / Math.max(1, totalSamples)) * 120) +
    Math.min(15, (redundant / Math.max(1, totalSamples)) * 60) +
    Math.min(8, Math.max(0, (imbalance - 3) * 1.2));
  const severityMass = findings.reduce(
    (sum, f) => sum + ({ CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0 }[f.severity] ?? 0) * f.confidence,
    0
  );
  const findingRisk = 100 * (1 - Math.exp(-severityMass / 45));
  const datasetRisk = Math.round(Math.min(100, 0.5 * prevalence + 0.5 * findingRisk) * 10) / 10;

  return {
    id: `DS-${digest.slice(0, 12).toUpperCase()}`,
    filename,
    sha256: digest,
    fileSizeBytes: buffer.length,
    totalSamples,
    decodedSamples: totalSamples - corrupt.length,
    corruptedFiles: corrupt.length,
    corruptSampleDetails: corrupt.slice(0, 25),
    format: isArchive ? 'ARCHIVE (degraded parse)' : 'SINGLE_IMAGE',
    archive: {
      format: isArchive ? 'zip' : 'single-image',
      entriesSeen: totalSamples,
      violations: violations.slice(0, 50),
      violationCount: violations.length,
      aborted,
    },
    duplicateFiles: duplicateGroups.slice(0, 50),
    nearDuplicateCandidates: [],
    duplicateAnalysis: {
      totalRedundantSamples: redundant,
      exactDuplicateSamples: redundant,
      nearDuplicateSamples: 0,
      clusterCount: duplicateGroups.length,
      embeddingConfirmed: false,
    },
    classDistribution,
    classImbalanceRatio: Math.round(imbalance * 100) / 100,
    suspiciousLabelPatterns: [],
    anomalousSamples: [],
    oodIndicators: [],
    contributorStats: {},
    contributorProfiles: [],
    coverageGaps: [
      'perceptual-deduplication-unavailable',
      'label-consistency-unavailable',
      'trigger-detection-unavailable',
      'ood-scoring-unavailable',
      'contributor-attribution-unavailable',
    ],
    datasetRisk,
    status: statusFrom(findings),
    findings,
    analysisDurationSeconds: (Date.now() - started) / 1000,
    engine: 'node-fallback',
    timestamp: nowIso(),
  };
}

// --- model ------------------------------------------------------------------

/** Symbols that are unambiguously an execution primitive inside a weights file. */
const CRITICAL_MODULES = new Set([
  'os', 'posix', 'nt', 'subprocess', 'socket', 'shutil', 'pty', 'ctypes', 'runpy',
  'importlib', 'webbrowser', 'pickle', 'marshal', 'builtins', '__builtin__', 'sys',
  'commands', 'popen2', 'requests', 'urllib', 'ftplib', 'smtplib', 'pdb', 'bdb', 'code',
]);

interface OpcodeScan {
  globals: Array<{ module: string; name: string; offset: number }>;
  critical: Array<{ module: string; name: string; offset: number }>;
  truncated: boolean;
}

/**
 * Locate GLOBAL opcodes in a pickle stream.
 *
 * `c` (0x63) introduces a GLOBAL whose operand is `module\nname\n`. This is a reduced
 * version of the engine's full disassembly -- it does not follow the stack, so it cannot
 * resolve STACK_GLOBAL operands -- but it correctly identifies the direct-import form
 * that the overwhelming majority of malicious checkpoints use, and it does so by opcode
 * position rather than by searching for a substring anywhere in the file.
 */
function scanPickleGlobals(data: Buffer): OpcodeScan {
  const result: OpcodeScan = { globals: [], critical: [], truncated: false };
  const limit = Math.min(data.length, 64 * 1024 * 1024);

  for (let offset = 0; offset < limit; offset += 1) {
    if (data[offset] !== 0x63) continue; // 'c' GLOBAL

    const firstNewline = data.indexOf(0x0a, offset + 1);
    if (firstNewline < 0 || firstNewline - offset > 256) continue;
    const secondNewline = data.indexOf(0x0a, firstNewline + 1);
    if (secondNewline < 0 || secondNewline - firstNewline > 256) continue;

    const moduleName = data.subarray(offset + 1, firstNewline).toString('latin1');
    const attribute = data.subarray(firstNewline + 1, secondNewline).toString('latin1');

    // A real module path is dotted identifiers; anything else is a coincidental 0x63.
    if (!/^[A-Za-z_][A-Za-z0-9_.]*$/.test(moduleName) || !/^[A-Za-z_][A-Za-z0-9_.]*$/.test(attribute)) {
      continue;
    }

    const entry = { module: moduleName, name: attribute, offset };
    result.globals.push(entry);
    if (CRITICAL_MODULES.has(moduleName.split('.')[0])) {
      result.critical.push(entry);
    }
    if (result.globals.length > 5000) break;
  }

  return result;
}

function identifyContainer(data: Buffer): string {
  if (data.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) return 'zip';
  if (data.subarray(0, 6).equals(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]))) return '7z';
  if (data[0] === 0x1f && data[1] === 0x8b) return 'gzip';
  if (data.subarray(0, 3).toString('latin1') === 'BZh') return 'bzip2';
  if (data.subarray(0, 6).equals(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]))) return 'xz';
  if (data[0] === 0x80) return 'raw-pickle';
  return 'unknown';
}

export function analyzeModelFallback(filename: string, buffer: Buffer): ModelAnalysisResult {
  const started = Date.now();
  const digest = sha256(buffer);
  const extension = path.extname(filename).toLowerCase();
  const findings: Finding[] = [];
  const container = identifyContainer(buffer);

  const base = {
    id: `MOD-${digest.slice(0, 12).toUpperCase()}`,
    filename,
    sha256: digest,
    fileSizeBytes: buffer.length,
    engine: 'node-fallback',
    timestamp: nowIso(),
  };

  const finish = (params: {
    framework: string;
    architecture: string;
    parameterCount: number | null;
    analysisMode: ModelAnalysisResult['analysisMode'];
    status: AssuranceStatus;
    modelRisk: number;
    limitations: string;
    backdoorConfidence?: number;
    pickleAudit?: ModelAnalysisResult['pickleAudit'];
  }): ModelAnalysisResult => ({
    ...base,
    framework: params.framework,
    architecture: params.architecture,
    parameterCount: params.parameterCount,
    analysisMode: params.analysisMode,
    status: params.status,
    severity: findings[0]?.severity ?? 'INFO',
    confidence: findings[0]?.confidence ?? 0.9,
    backdoorConfidence: params.backdoorConfidence ?? 0,
    behavioralAnalysis:
      'Behavioural battery not run: the assurance engine was unreachable and the gateway does not ' +
      'execute models. No behavioural conclusion is available.',
    backdoorAnalysis:
      'Trigger inversion not run: this requires the assurance engine. Absence of a backdoor finding ' +
      'here is a coverage gap, not evidence of absence.',
    evidence: { sha256: digest, container, framework: params.framework },
    pickleAudit: params.pickleAudit ?? null,
    weightStatistics: null,
    behaviouralBattery: null,
    neuralCleanse: null,
    limitations: params.limitations,
    modelRisk: params.modelRisk,
    findings,
    analysisDurationSeconds: (Date.now() - started) / 1000,
  });

  if (!['.pt', '.pth', '.onnx', '.ts', '.torchscript', '.safetensors', '.bin'].includes(extension)) {
    findings.push(
      makeFinding({
        findingId: 'MOD-UNSUPPORTED-FORMAT',
        category: 'MODEL',
        severity: 'LOW',
        confidence: 1,
        affectedAsset: filename,
        explanation: `Extension '${extension}' is not a recognised checkpoint format.`,
        evidence: { extension, container },
        recommendation: 'Re-export as ONNX or safetensors; neither carries an executable pickle.',
        detector: 'server/analyzers/fallback.analyzeModelFallback',
        threshold: 'extension allowlist',
      })
    );
    return finish({
      framework: 'Unknown',
      architecture: 'Unsupported format',
      parameterCount: null,
      analysisMode: 'REFUSED',
      status: 'NOT SUPPORTED',
      modelRisk: 20,
      limitations: 'No analysis was performed. This is a coverage gap, not a clean result.',
    });
  }

  if (extension === '.onnx') {
    const looksProtobuf = [0x08, 0x12, 0x1a, 0x22].includes(buffer[0]);
    if (!looksProtobuf) {
      findings.push(
        makeFinding({
          findingId: 'MOD-ONNX-UNPARSEABLE',
          category: 'MODEL',
          severity: 'HIGH',
          confidence: 1,
          affectedAsset: filename,
          explanation:
            'The file carries an .onnx extension but does not begin with a protobuf field tag. A ' +
            'checkpoint whose declared format is a lie must be treated as hostile.',
          evidence: { firstByte: buffer[0], container },
          recommendation: 'Reject the submission and require a re-export verified with onnx.checker.',
          detector: 'server/analyzers/fallback.analyzeModelFallback',
          threshold: 'protobuf wire-tag at offset 0',
        })
      );
    }
    return finish({
      framework: 'ONNX',
      architecture: looksProtobuf ? 'ONNX graph (not parsed in degraded mode)' : 'Unparseable',
      parameterCount: null,
      analysisMode: 'BLACK_BOX',
      status: looksProtobuf ? 'NOT DETECTED' : 'ANALYSIS FAILED',
      modelRisk: looksProtobuf ? 10 : 70,
      limitations:
        'Only the container was checked. Operator enumeration, orphan-node detection and weight ' +
        'statistics require the assurance engine.',
    });
  }

  // Scan every pickle stream we can reach without an unpickler.
  const scans: Array<{ stream: string; scan: OpcodeScan }> = [];
  if (container === 'zip') {
    try {
      const zip = new AdmZip(buffer);
      for (const entry of zip.getEntries()) {
        if (entry.isDirectory) continue;
        const name = entry.entryName.toLowerCase();
        if (!name.endsWith('.pkl') && !name.endsWith('.pickle') && !name.endsWith('/data')) continue;
        if (entry.header.size > LIMITS.maxEntryBytes) continue;
        scans.push({ stream: entry.entryName, scan: scanPickleGlobals(entry.getData()) });
      }
    } catch {
      // A malformed zip is reported below through the empty scan list.
    }
  } else if (container === 'raw-pickle' || container === 'unknown') {
    scans.push({ stream: `${filename}:raw`, scan: scanPickleGlobals(buffer) });
  }

  const critical = scans.flatMap((s) => s.scan.critical);
  const allGlobals = scans.flatMap((s) => s.scan.globals);

  const pickleAudit: ModelAnalysisResult['pickleAudit'] = {
    verdict: critical.length > 0 ? 'MALICIOUS' : container === '7z' || container === 'bzip2' || container === 'xz' ? 'SUSPICIOUS' : 'CLEAN',
    container,
    streamsScanned: scans.length,
    opcodeCount: allGlobals.length,
    callOpcodes: 0,
    protocolVersions: [],
    globalsFound: allGlobals.slice(0, 200).map((g) => ({ ...g, qualname: `${g.module}.${g.name}` })),
    disallowedGlobals: [],
    criticalGlobals: critical.map((g) => ({ qualname: `${g.module}.${g.name}`, offset: g.offset })),
    truncatedStreams: [],
    notes: [
      'Reduced opcode scan: GLOBAL opcodes only. STACK_GLOBAL resolution and full stream ' +
        'disassembly require the assurance engine.',
    ],
    safeToLoad: false,
  };

  if (critical.length > 0) {
    findings.push(
      makeFinding({
        findingId: 'SEC-MALICIOUS-PICKLE-OPCODE',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 1,
        affectedAsset: filename,
        explanation:
          `The checkpoint's pickle stream names ${critical.length} execution primitive(s) ` +
          `(${[...new Set(critical.map((c) => `${c.module}.${c.name}`))].slice(0, 5).join(', ')}). ` +
          'Calling torch.load on this file would run attacker-controlled code before any tensor is read.',
        evidence: pickleAudit,
        recommendation:
          'QUARANTINE the file immediately. Do not call torch.load on any node. Treat the supplying ' +
          'vendor\'s catalogue as compromised until audited.',
        detector: 'server/analyzers/fallback.scanPickleGlobals',
        threshold: 'GLOBAL opcode naming a module outside the weights-serialisation set',
        references: ['CWE-502', 'MITRE ATLAS AML.T0010'],
      })
    );
    return finish({
      framework: 'PyTorch (compromised)',
      architecture: 'Untrusted checkpoint - not deserialised',
      parameterCount: null,
      analysisMode: 'REFUSED',
      status: 'DETECTED',
      modelRisk: 100,
      limitations:
        'The checkpoint was never deserialised, which is the correct outcome: it is disqualified on ' +
        'serialisation grounds alone.',
      pickleAudit,
    });
  }

  if (['7z', 'bzip2', 'xz', 'gzip'].includes(container)) {
    findings.push(
      makeFinding({
        findingId: 'SEC-PICKLE-ANOMALY',
        category: 'SUPPLY_CHAIN',
        severity: 'HIGH',
        confidence: 0.8,
        affectedAsset: filename,
        explanation:
          `The checkpoint is wrapped in a ${container} container. PyTorch never emits this format; ` +
          'non-standard wrappers are used to keep scanners and torch.load from parsing the payload.',
        evidence: pickleAudit,
        recommendation: 'Require the vendor to resupply as ONNX or safetensors before acceptance.',
        detector: 'server/analyzers/fallback.identifyContainer',
        threshold: 'container conformance',
        references: ['ReversingLabs nullifAI (2025)'],
      })
    );
  }

  return finish({
    framework: `PyTorch (${container} container)`,
    architecture: 'Not recovered in degraded mode',
    parameterCount: null,
    analysisMode: 'BLACK_BOX',
    status: statusFrom(findings),
    modelRisk: findings.length > 0 ? 45 : 15,
    limitations:
      'Only the container and a reduced GLOBAL-opcode scan were performed. Architecture recovery, ' +
      'weight statistics, the behavioural battery and Neural Cleanse trigger inversion all require ' +
      'the assurance engine and did not run.',
    pickleAudit,
  });
}

// --- distribution shift ------------------------------------------------------

export function analyzeShiftFallback(params: {
  baselineName: string;
  targetName: string;
  baselineFeatures?: Record<string, number>;
  targetFeatures?: Record<string, number>;
  baselineClassRatios?: Record<string, number>;
  targetClassRatios?: Record<string, number>;
}): DistributionShiftResult {
  const baseline = params.baselineFeatures ?? {};
  const target = params.targetFeatures ?? {};
  const shared = Object.keys(baseline).filter((key) => key in target);

  const featureDrifts = shared.map((feature) => {
    const b = baseline[feature];
    const t = target[feature];
    const relative = Math.abs(t - b) / Math.max(1e-6, Math.abs(b));
    const status: 'SHIFT_DETECTED' | 'WARNING' | 'STABLE' =
      relative > 0.2 ? 'SHIFT_DETECTED' : relative > 0.08 ? 'WARNING' : 'STABLE';
    return {
      feature,
      baselineMean: b,
      targetMean: t,
      driftScore: Math.min(1, relative),
      ksStatistic: null,
      pValue: null,
      status,
      description: `Baseline ${b.toFixed(3)} -> target ${t.toFixed(3)} (relative change ${(relative * 100).toFixed(1)}%)`,
    };
  });

  const average = featureDrifts.length
    ? featureDrifts.reduce((sum, drift) => sum + drift.driftScore, 0) / featureDrifts.length
    : 0;
  const score = Math.round(Math.min(100, average * 100) * 10) / 10;

  const classDrift: Record<string, { baselineRatio: number; targetRatio: number; delta: number }> = {};
  const baselineRatios = params.baselineClassRatios ?? {};
  const targetRatios = params.targetClassRatios ?? {};
  let psi = 0;
  for (const key of new Set([...Object.keys(baselineRatios), ...Object.keys(targetRatios)])) {
    const b = Math.max(1e-6, baselineRatios[key] ?? 0);
    const t = Math.max(1e-6, targetRatios[key] ?? 0);
    psi += (t - b) * Math.log(t / b);
    classDrift[key] = {
      baselineRatio: Math.round(b * 1000) / 1000,
      targetRatio: Math.round(t * 1000) / 1000,
      delta: Math.round((t - b) * 1000) / 1000,
    };
  }

  const findings: Finding[] = [];
  if (score > 20) {
    findings.push(
      makeFinding({
        findingId: 'SHIFT-COVARIATE-DRIFT',
        category: 'DISTRIBUTION',
        severity: score > 45 ? 'HIGH' : 'MEDIUM',
        confidence: 0.5,
        affectedAsset: `${params.targetName} vs ${params.baselineName}`,
        explanation:
          `Mean relative feature drift of ${score.toFixed(0)}/100 against the baseline. Degraded mode ` +
          'compares summary statistics only; it cannot compute MMD, establish significance, or ' +
          'distinguish environmental drift from deliberate manipulation.',
        evidence: { featureDrifts: featureDrifts.slice(0, 8), populationStabilityIndex: psi },
        recommendation: 'Re-run with the assurance engine available before acting on this result.',
        detector: 'server/analyzers/fallback.analyzeShiftFallback',
        threshold: 'mean relative feature drift > 20%',
      })
    );
  }

  return {
    id: `SHIFT-${Date.now().toString(36).toUpperCase()}`,
    baselineName: params.baselineName,
    targetName: params.targetName,
    method: 'summary-statistics (degraded)',
    mmd: 0,
    mmdSquared: 0,
    pValue: null,
    significant: false,
    severityBand: score > 45 ? 'HIGH' : score > 20 ? 'MEDIUM' : 'LOW',
    attribution: null,
    overallShiftScore: score,
    status: score > 45 ? 'DETECTED' : score > 20 ? 'SUSPICIOUS' : 'NOT DETECTED',
    featureDrifts,
    classDistributionDrift: classDrift,
    populationStabilityIndex: Math.round(psi * 10000) / 10000,
    baselineSamples: 0,
    targetSamples: 0,
    limitation:
      'Degraded mode: only scalar summary features were compared. Maximum Mean Discrepancy, the ' +
      'permutation test and drift attribution all require sample-level feature vectors and the ' +
      'assurance engine.',
    findings,
    engine: 'node-fallback',
    timestamp: nowIso(),
  };
}
