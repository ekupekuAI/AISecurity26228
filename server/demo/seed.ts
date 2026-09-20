/**
 * Evaluation dataset for demonstration and acceptance testing.
 *
 * Every record written here is tagged `is_demo = 1` so it can be purged without touching
 * operational evidence, and the inference record is *genuinely* sealed and *genuinely*
 * tampered -- the STOP_SIGN prediction is sealed, the digest is computed over it, and
 * then SPEED_LIMIT is stored. Verifying that record really does recompute a different
 * digest. Nothing here is a hardcoded "TAMPERED" string, because a demo that fakes its
 * own result proves nothing about the system.
 *
 * The scenario follows the problem statement's section 10 case study.
 */

import crypto from 'node:crypto';
import { appendAuditEvent } from '../db/audit.js';
import { claimNonce, clearDemoData, ownerTag, saveAnalysis, saveInferenceRecord } from '../db/repositories.js';
import type { FindingRecord } from '../db/repositories.js';
import { log } from '../logger.js';
import { canonicalDocument, seal, verify } from '../provenance/records.js';
import type { InferenceRecordInput } from '../provenance/records.js';

function sha256(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

const DATASET_SHA = sha256('contributor_bravo_yolov8_pack.zip::evaluation');
const MODEL_SHA = sha256('traffic_recon_resnet18.pth::evaluation');

export interface SeedSummary {
  message: string;
  datasetAnalysisId: string;
  modelAnalysisId: string;
  shiftAnalysisId: string;
  inferenceRecordId: string;
  tamperDemonstration: {
    sealedPrediction: string;
    presentedPrediction: string;
    sealedDigest: string;
    recomputedDigest: string;
    verificationStatus: string;
    alteredFields: string[];
  };
}

export function seedEvaluationData(actor: string, owner?: string | null): SeedSummary {
  const ownerId = owner ?? null;
  // Namespace the fixed demo ids by owner so two operators can each hold the evaluation
  // scenario without colliding on the analyses/inference_records primary keys.
  const sfx = ownerTag(ownerId) ? `-${ownerTag(ownerId)}` : '';
  const dsId = `DS-EVAL-CONTRIB-BRAVO${sfx}`;
  const modId = `MOD-EVAL-PREACT-RN18${sfx}`;
  const shiftId = `SHIFT-EVAL-FOP-IR${sfx}`;
  const infId1 = `INF-EVAL-00941${sfx}`;
  const infId2 = `INF-EVAL-00942${sfx}`;
  // Scoped to this owner so it never wipes another operator's demo data.
  clearDemoData(actor, ownerId ?? undefined);

  const datasetFindings: FindingRecord[] = [
    {
      findingId: 'DS-BACKDOOR-TRIGGER-INJECTION',
      category: 'DATASET',
      severity: 'CRITICAL',
      confidence: 0.96,
      affectedAsset: 'contributor_bravo_yolov8_pack.zip (12 samples in 1 trigger cluster)',
      explanation:
        '12 samples carry an identical 16x16 perturbation at identical coordinates in the ' +
        'bottom-right corner. Spatial consistency across independent samples is the functional ' +
        'requirement of a backdoor trigger and does not occur in natural imagery.',
      evidence: {
        clusters: [
          {
            label: 'military_vehicle',
            memberCount: 12,
            bbox: [208, 208, 224, 224],
            spatialConsistency: 0.97,
            meanPerturbationMagnitude: 68.4,
            suspectedFamily: 'BadNets / localised patch trigger (low-entropy, high-contrast stamp)',
          },
        ],
        targetLabels: ['military_vehicle'],
      },
      recommendation:
        'QUARANTINE the corpus. Revoke Contributor Bravo\'s ingest pipeline and retrain any model ' +
        'that consumed this data from a clean checkpoint.',
      detector: 'vision.triggers.find_consensus_triggers',
      threshold: 'modified z-score > 3.0 on residual peak, >=3 samples agreeing within 6px',
      references: ['Gu et al., BadNets (2017)'],
    },
    {
      findingId: 'DS-LABEL-FLIPPING',
      category: 'DATASET',
      severity: 'HIGH',
      confidence: 0.93,
      affectedAsset: 'contributor_bravo_yolov8_pack.zip (32 samples)',
      explanation:
        '32 samples sit inside another class\'s embedding neighbourhood. 32 samples flow from ' +
        "'military_vehicle' to 'civilian_vehicle', 87% of all flagged samples and 3.2% of the source " +
        'class. A single dominant direction at this concentration is characteristic of targeted ' +
        'label flipping rather than diffuse annotation error.',
      evidence: {
        classPairFlows: [
          { fromLabel: 'military_vehicle', toLabel: 'civilian_vehicle', count: 32, shareOfSourceClass: 0.032 },
        ],
        estimatedNoiseRate: 0.0089,
        systematicManipulation: true,
      },
      recommendation:
        "Quarantine Contributor Bravo's annotations and re-label the affected samples under " +
        'multi-analyst consensus.',
      detector: 'vision.label_noise.detect_label_noise',
      threshold: 'k=15 neighbour disagreement >= 75% and margin >= 20%',
      references: ['Northcutt et al., Confident Learning (JAIR 2021)'],
    },
    {
      findingId: 'DS-DUPLICATE-FLOODING',
      category: 'DATASET',
      severity: 'HIGH',
      confidence: 0.99,
      affectedAsset: 'contributor_bravo_yolov8_pack.zip (80 redundant samples)',
      explanation:
        '80 samples (0.8% of the corpus) are exact or perceptual duplicates of another sample. ' +
        'This exceeds the flooding threshold, which inflates a contributor\'s apparent share of the ' +
        'corpus and biases the trained model toward it.',
      evidence: {
        exactDuplicateSamples: 47,
        nearDuplicateSamples: 33,
        clusterCount: 11,
        floodingContributors: { Contributor_Bravo: 78, Contributor_Alpha: 2 },
      },
      recommendation: 'Deduplicate the corpus and audit the flooding contributor\'s submission history.',
      detector: 'vision.duplicates.find_near_duplicates',
      threshold: 'pHash Hamming <= 5 AND embedding cosine > 0.98',
    },
    {
      findingId: 'DS-OUT-OF-DISTRIBUTION',
      category: 'DATASET',
      severity: 'MEDIUM',
      confidence: 0.81,
      affectedAsset: 'contributor_bravo_yolov8_pack.zip (21 samples)',
      explanation:
        '21 samples lie beyond the 99th percentile of Mahalanobis distance to their nearest class ' +
        'centroid. These are the corpus\'s blind spots: content the trained model will be asked to ' +
        'handle but was never meaningfully supervised on.',
      evidence: { outlierCount: 21, thresholdDistance: 41.7, medianDistance: 12.3 },
      recommendation: 'Review the outliers for domain relevance; remove padding content and cover genuine gaps.',
      detector: 'vision.ood.detect_ood',
      threshold: 'Mahalanobis distance > P99 of corpus',
      references: ['Lee et al., NeurIPS 2018'],
    },
    {
      findingId: 'DS-CONTRIBUTOR-RISK',
      category: 'DATASET',
      severity: 'HIGH',
      confidence: 0.9,
      affectedAsset: 'Contributor: Contributor_Bravo',
      explanation:
        "Source 'Contributor_Bravo' supplied 4,100 samples with a 3.5% defect density, yielding a " +
        'source risk of 84/100. Attribution strategy: manifest.',
      evidence: {
        name: 'Contributor_Bravo',
        sampleCount: 4100,
        triggerSamples: 12,
        labelSuspects: 32,
        totalDefects: 143,
        riskScore: 84.0,
      },
      recommendation:
        "Suspend ingest from 'Contributor_Bravo' pending a supply-chain review of their collection " +
        'and annotation process.',
      detector: 'ingest.contributors.aggregate',
      threshold: 'source risk >= 60 with >= 20 samples',
    },
  ];

  const datasetPayload = {
    id: dsId,
    filename: 'contributor_bravo_yolov8_pack.zip',
    sha256: DATASET_SHA,
    fileSizeBytes: 248_920_150,
    totalSamples: 10_000,
    decodedSamples: 9_994,
    corruptedFiles: 6,
    format: 'YOLO',
    classDistribution: {
      military_vehicle: 3420,
      civilian_vehicle: 2850,
      pedestrian_personnel: 1980,
      checkpoint_barrier: 1750,
    },
    duplicateAnalysis: { totalRedundantSamples: 80, exactDuplicateSamples: 47, nearDuplicateSamples: 33 },
    triggerAnalysis: {
      confirmedSamples: 12,
      clusterCount: 1,
      consensusAvailable: true,
      clusters: [{ label: 'military_vehicle', memberCount: 12, bbox: [208, 208, 224, 224], spatialConsistency: 0.97 }],
    },
    labelAnalysis: { suspectCount: 32, systematicManipulation: true, estimatedNoiseRate: 0.0089 },
    oodAnalysis: { outlierCount: 21, available: true },
    contributorProfiles: [
      {
        name: 'Contributor_Bravo',
        sampleCount: 4100,
        exactDuplicates: 47,
        nearDuplicates: 31,
        labelSuspects: 32,
        triggerSamples: 12,
        oodSamples: 17,
        corruptSamples: 4,
        totalDefects: 143,
        defectDensityPercent: 3.488,
        riskScore: 84.0,
        riskDrivers: [
          '12 sample(s) carrying backdoor trigger artifacts (0.3% of this source)',
          '32 label-consistency failure(s) (0.8%)',
          '78 redundant sample(s) from duplicate flooding',
        ],
      },
      {
        name: 'Contributor_Alpha',
        sampleCount: 5900,
        exactDuplicates: 0,
        nearDuplicates: 2,
        labelSuspects: 0,
        triggerSamples: 0,
        oodSamples: 4,
        corruptSamples: 2,
        totalDefects: 8,
        defectDensityPercent: 0.136,
        riskScore: 6.2,
        riskDrivers: ['2 redundant sample(s) from duplicate flooding', '4 out-of-distribution sample(s)'],
      },
    ],
    contributorAttributionStrategy: 'manifest',
    datasetRisk: 78.0,
    status: 'DETECTED',
    engine: 'evaluation-fixture',
    findings: datasetFindings,
    timestamp: new Date().toISOString(),
  };

  const dataset = saveAnalysis({
    id: dsId,
    type: 'DATASET',
    filename: 'contributor_bravo_yolov8_pack.zip',
    sha256: DATASET_SHA,
    fileSizeBytes: 248_920_150,
    status: 'DETECTED',
    riskScore: 78.0,
    engine: 'evaluation-fixture',
    payload: datasetPayload,
    findings: datasetFindings,
    contributors: datasetPayload.contributorProfiles,
    performedBy: actor,
    ownerId,
    isDemo: true,
  });

  const modelFindings: FindingRecord[] = [
    {
      findingId: 'MOD-NEURAL-CLEANSE-TRIGGER',
      category: 'MODEL',
      severity: 'CRITICAL',
      confidence: 0.91,
      affectedAsset: 'traffic_recon_resnet18.pth (target class 7)',
      explanation:
        'Optimisation-based trigger inversion recovered a universal perturbation that forces class 7 ' +
        'while covering only 2.10% of the input. Its L1 mask norm is 2.84 MADs below the across-class ' +
        'median, past the 2.0 detection threshold. A class reachable by a perturbation this much ' +
        'smaller than every other class is the defining signature of an implanted shortcut.',
      evidence: {
        flaggedClasses: [7],
        maxAnomalyIndex: 2.84,
        medianL1: 412.6,
        anomalyIndexThreshold: 2.0,
        suspectedFamily: 'BadNets / localised patch trigger',
        classesScanned: 10,
        classesTotal: 10,
      },
      recommendation:
        'QUARANTINE the checkpoint. Do not deploy. Retrain from a trusted base or obtain a re-signed ' +
        'checkpoint from the vendor with provenance evidence.',
      detector: 'modelscan.neural_cleanse.run',
      threshold: 'MAD anomaly index > 2.0 with L1 below median and attack success >= 0.85',
      references: ['Wang et al., Neural Cleanse (IEEE S&P 2019)'],
    },
    {
      findingId: 'MOD-BEHAVIOURAL-BACKDOOR-RESPONSE',
      category: 'MODEL',
      severity: 'CRITICAL',
      confidence: 0.88,
      affectedAsset: 'traffic_recon_resnet18.pth (target class 7)',
      explanation:
        "Under the 'badnets_corner_patch' trigger battery, 98.6% of reference inputs changed " +
        'prediction, and 99.1% of those flips landed on the single class 7. Ordinary perturbation ' +
        'sensitivity scatters predictions across classes; concentration this high is a directed response.',
      evidence: {
        batteries: [
          { name: 'badnets_corner_patch', flipRate: 0.986, flipConcentration: 0.991, targetClass: 7, verdict: 'STRONG_BACKDOOR_INDICATION' },
          { name: 'checkerboard_stamp', flipRate: 0.213, flipConcentration: 0.64, targetClass: 7, verdict: 'STABLE' },
        ],
      },
      recommendation: 'QUARANTINE the checkpoint and escalate to the model validation authority.',
      detector: 'modelscan.battery.run_battery',
      threshold: 'flip rate >= 50% with >= 85% concentration on one class',
      references: ['Gu et al., BadNets (2017)'],
    },
  ];

  const model = saveAnalysis({
    id: modId,
    type: 'MODEL',
    filename: 'traffic_recon_resnet18.pth',
    sha256: MODEL_SHA,
    fileSizeBytes: 44_781_920,
    status: 'DETECTED',
    riskScore: 85.0,
    engine: 'evaluation-fixture',
    analysisMode: 'WHITE_BOX',
    payload: {
      id: modId,
      filename: 'traffic_recon_resnet18.pth',
      sha256: MODEL_SHA,
      framework: 'PyTorch (zip container)',
      architecture: 'resnet18 (10 classes, reconstructed and strictly loaded)',
      parameterCount: 11_181_642,
      analysisMode: 'WHITE_BOX',
      status: 'DETECTED',
      backdoorConfidence: 0.91,
      pickleAudit: { verdict: 'CLEAN', container: 'zip', opcodeCount: 4366, safeToLoad: true },
      neuralCleanse: {
        ran: true,
        classesScanned: 10,
        classesTotal: 10,
        maxAnomalyIndex: 2.84,
        flaggedClasses: [7],
        anomalyIndexThreshold: 2.0,
        backdoorConfidence: 0.89,
      },
      behaviouralBattery: { ran: true, backdoorConfidence: 0.85, suspectedTargetClass: 7 },
      limitations:
        'Access obtained: WHITE_BOX. Neural Cleanse assumes a small, static, input-agnostic trigger ' +
        'and a single target class. All-to-all backdoors produce no MAD outlier; input-aware families ' +
        'such as WaNet are outside its model entirely.',
      modelRisk: 85.0,
      engine: 'evaluation-fixture',
      findings: modelFindings,
      timestamp: new Date().toISOString(),
    },
    findings: modelFindings,
    performedBy: actor,
    ownerId,
    isDemo: true,
  });

  const shift = saveAnalysis({
    id: shiftId,
    type: 'DISTRIBUTION',
    filename: 'forward_observation_post_ir_stream_vs_daylight_baseline',
    sha256: sha256('shift::evaluation'),
    fileSizeBytes: 0,
    status: 'NOT DETECTED',
    riskScore: 18.0,
    engine: 'evaluation-fixture',
    payload: {
      id: shiftId,
      baselineName: 'fop_sensor_daylight_baseline',
      targetName: 'forward_observation_post_ir_stream',
      method: 'mmd-rbf-permutation',
      mmd: 0.12,
      pValue: 0.0348,
      significant: true,
      severityBand: 'MEDIUM',
      attribution: {
        verdict: 'ENVIRONMENTAL_DRIFT',
        confidence: 0.82,
        displacementConcentration: 0.19,
        photometricExplainedFraction: 0.81,
        outlierSampleCount: 3,
        reasoning:
          'Displacement is spread evenly across the batch (Gini 0.19) and 81% of it lies along ' +
          'photometric axes. This is the profile of a sensor, illumination or weather change, not of ' +
          'injected samples.',
      },
      overallShiftScore: 18.0,
      status: 'NOT DETECTED',
      engine: 'evaluation-fixture',
      findings: [],
      timestamp: new Date().toISOString(),
    },
    findings: [],
    performedBy: actor,
    ownerId,
    isDemo: true,
  });

  // --- the tamper demonstration, performed for real ---------------------------

  const authentic: InferenceRecordInput = {
    recordId: infId1,
    inputImageSha256: sha256('forward_observation_post_frame_00941'),
    modelIdentifier: 'traffic_recon_resnet18.pth',
    modelSha256: MODEL_SHA,
    inferenceConfig: {
      input_resolution: [224, 224],
      mean_norm: [0.485, 0.456, 0.406],
      std_norm: [0.229, 0.224, 0.225],
      confidence_threshold: 0.5,
    },
    prediction: 'STOP_SIGN',
    confidence: 0.9841,
    timestampUtc: new Date().toISOString(),
    nonce: crypto.randomBytes(16).toString('hex'),
  };

  // Seal the authentic record. This digest is what an honest pipeline would publish.
  const sealed = seal(authentic);

  claimNonce({
    nonce: authentic.nonce,
    recordId: authentic.recordId,
    recordHash: sealed.recordSha256,
    inputHash: authentic.inputImageSha256,
    modelHash: authentic.modelSha256,
    prediction: authentic.prediction,
  });

  // Now alter the prediction in transit, exactly as the case study describes, and verify
  // the altered payload against the authentic digest.
  const tampered: InferenceRecordInput = { ...authentic, prediction: 'SPEED_LIMIT' };
  const verification = verify({
    record: tampered,
    expectedHash: sealed.recordSha256,
    signature: sealed.signature,
    signingKeyId: sealed.signingKeyId,
    reference: canonicalDocument(authentic),
  });

  saveInferenceRecord({
    recordId: authentic.recordId,
    inputHash: tampered.inputImageSha256,
    modelIdentifier: tampered.modelIdentifier,
    modelHash: tampered.modelSha256,
    configuration: tampered.inferenceConfig,
    prediction: tampered.prediction,
    confidence: tampered.confidence,
    timestamp: tampered.timestampUtc,
    nonce: tampered.nonce,
    recordHash: sealed.recordSha256,
    signature: sealed.signature,
    signingKeyId: sealed.signingKeyId,
    canonical: JSON.stringify(canonicalDocument(authentic)),
    // Whatever the verifier actually concluded -- not a hardcoded label.
    status: verification.status,
    sealedBy: actor,
    ownerId,
    isDemo: true,
  });

  // A second, untampered record so the console shows both outcomes side by side.
  const cleanRecord: InferenceRecordInput = {
    recordId: infId2,
    inputImageSha256: sha256('forward_observation_post_frame_00942'),
    modelIdentifier: 'traffic_recon_resnet18.pth',
    modelSha256: MODEL_SHA,
    inferenceConfig: authentic.inferenceConfig,
    prediction: 'PEDESTRIAN',
    confidence: 0.9127,
    timestampUtc: new Date().toISOString(),
    nonce: crypto.randomBytes(16).toString('hex'),
  };
  const cleanSealed = seal(cleanRecord);
  claimNonce({
    nonce: cleanRecord.nonce,
    recordId: cleanRecord.recordId,
    recordHash: cleanSealed.recordSha256,
    inputHash: cleanRecord.inputImageSha256,
    modelHash: cleanRecord.modelSha256,
    prediction: cleanRecord.prediction,
  });
  saveInferenceRecord({
    recordId: cleanRecord.recordId,
    inputHash: cleanRecord.inputImageSha256,
    modelIdentifier: cleanRecord.modelIdentifier,
    modelHash: cleanRecord.modelSha256,
    configuration: cleanRecord.inferenceConfig,
    prediction: cleanRecord.prediction,
    confidence: cleanRecord.confidence,
    timestamp: cleanRecord.timestampUtc,
    nonce: cleanRecord.nonce,
    recordHash: cleanSealed.recordSha256,
    signature: cleanSealed.signature,
    signingKeyId: cleanSealed.signingKeyId,
    canonical: JSON.stringify(cleanSealed.document),
    status: 'VERIFIED',
    sealedBy: actor,
    ownerId,
    isDemo: true,
  });

  appendAuditEvent({
    eventType: `INFERENCE_${verification.status}`,
    assetName: authentic.recordId,
    assetHash: authentic.inputImageSha256,
    severity: 'CRITICAL',
    actor,
    description:
      `Adversarial payload interception: prediction altered from '${authentic.prediction}' to ` +
      `'${tampered.prediction}' in transit. Recomputed digest ${verification.computedHash.slice(0, 12)}... ` +
      `does not match the sealed ${sealed.recordSha256.slice(0, 12)}... Verdict: ${verification.status}.`,
    metadata: {
      sealedDigest: sealed.recordSha256,
      recomputedDigest: verification.computedHash,
      alteredFields: verification.alteredFields,
      signatureValid: verification.signatureValid,
    },
  });

  log.info('evaluation data seeded', {
    actor,
    tamperStatus: verification.status,
    alteredFields: verification.alteredFields,
  });

  return {
    message:
      'Evaluation scenario loaded. The tampered inference record was sealed and verified for real: ' +
      `the verifier independently returned ${verification.status}.`,
    datasetAnalysisId: dataset.analysisId,
    modelAnalysisId: model.analysisId,
    shiftAnalysisId: shift.analysisId,
    inferenceRecordId: authentic.recordId,
    tamperDemonstration: {
      sealedPrediction: authentic.prediction,
      presentedPrediction: tampered.prediction,
      sealedDigest: sealed.recordSha256,
      recomputedDigest: verification.computedHash,
      verificationStatus: verification.status,
      alteredFields: verification.alteredFields,
    },
  };
}
