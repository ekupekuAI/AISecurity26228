/**
 * Methodology.
 *
 * This page is documentation, not a result. Every threshold quoted here is the constant
 * that actually ships in `ml-engine/core/config.py`, and every "not covered" row is a
 * real gap rather than a hedge. An assurance tool that will not say what it cannot see is
 * asking to be trusted on faith, which is precisely the thing the pipeline is supposed to
 * stop doing.
 */

import React, { useEffect, useRef, useState } from 'react';
import { motion, useScroll, useTransform } from 'motion/react';
import {
  Binary,
  BookOpen,
  Boxes,
  Braces,
  CircuitBoard,
  Database,
  Fingerprint,
  Gavel,
  Microscope,
  Scale,
  ShieldAlert,
  Waves,
  XCircle,
} from 'lucide-react';
import { Badge, Card, CardHeader, Reveal, cn } from '../../ui/primitives.js';

interface Detector {
  name: string;
  basis: string;
  threshold: string;
  reference?: string;
}

interface Section {
  id: string;
  title: string;
  icon: React.ReactNode;
  lede: string;
  detectors: Detector[];
  gaps?: string[];
}

const SECTIONS: Section[] = [
  {
    id: 'dataset',
    title: 'Training-data integrity',
    icon: <Database size={15} />,
    lede: 'Four independent detectors run over every decoded sample. They are deliberately different in kind, because a single family of evidence is a single point of failure.',
    detectors: [
      {
        name: 'Exact duplicate flooding',
        basis: 'SHA-256 grouping over every decoded sample, then union-find clustering and per-contributor attribution.',
        threshold: 'any byte-identical group; flooding declared above 2% of the corpus',
      },
      {
        name: 'Near-duplicate flooding',
        basis: 'DCT perceptual hash indexed in a BK-tree for sublinear radius queries, confirmed by ResNet-18 embedding cosine. Two stages because pHash alone over-reports on flat imagery and embeddings alone are too slow for a full pairwise sweep.',
        threshold: 'pHash Hamming ≤ 5 AND cosine ≥ 0.98',
      },
      {
        name: 'Label manipulation',
        basis: 'k-nearest-neighbour clean-feature cross-validation in embedding space, followed by directed class-pair flow analysis that separates a targeted A→B flip from diffuse annotation noise.',
        threshold: 'k = 15, neighbour disagreement ≥ 0.85, margin ≥ 0.40',
        reference: 'Northcutt et al., Confident Learning, JAIR 2021',
      },
      {
        name: 'Backdoor trigger injection',
        basis: 'Residuals against both the per-class median and the corpus-wide median — the second pass exists because a class poisoned above roughly half its samples contaminates its own median. Candidates are clustered spatially, then gated on Bonferroni-corrected Poisson significance, pattern agreement, locality ratio and contrast against samples drawn from outside the class.',
        threshold: 'high-frequency z ≥ 3.5, patch/global variance ≥ 6.0, pattern agreement ≥ 0.80, locality ≥ 2.0, cluster α = 0.01',
        reference: 'Gu et al., BadNets 2017; Chen et al., Targeted Backdoor Attacks 2017',
      },
      {
        name: 'Out-of-distribution content',
        basis: 'Mahalanobis distance to class centroids under a Ledoit-Wolf shrunk pooled covariance, computed through an expanded quadratic form so the whole corpus scores in one pass.',
        threshold: '99th percentile of the corpus distance distribution, ≥ 12 samples per class',
        reference: 'Lee et al., NeurIPS 2018',
      },
      {
        name: 'Archive safety',
        basis: 'Four-way bomb guard and path normalisation applied before a single byte is decoded. Nothing from an archive is ever written to disk, so traversal is reported as evidence rather than merely blocked.',
        threshold: '2 GiB total, 256 MiB per entry, 200 000 entries, 200:1 compression ratio',
        reference: 'CWE-22, CWE-409, CWE-59',
      },
    ],
    gaps: [
      'Clean-label poisoning (Poison Frogs, Sleeper Agent). The label stays correct and the perturbation stays imperceptible, so neither the label detector nor the trigger detector has anything to fire on. Detecting it requires gradient-level analysis against the training run itself.',
      'Input-aware and warping backdoors (WaNet, BppAttack). The perturbation differs per sample by construction, so no cross-sample consensus exists to find.',
      'Semantically identical scenes shot from a different angle are not duplicates, and are correctly not flagged. A corpus that is uniformly out-of-domain reports few internal outliers, because outliers are measured relative to the submission, not to an external reference.',
    ],
  },
  {
    id: 'model',
    title: 'Model integrity',
    icon: <CircuitBoard size={15} />,
    lede: 'The serialisation audit always runs and always runs first. Everything that follows depends on whether the checkpoint could be loaded at all, so the console reports the access mode alongside every verdict.',
    detectors: [
      {
        name: 'Serialisation audit',
        basis: 'Full pickletools opcode disassembly against a symbol allowlist. Non-standard containers are unwrapped, and a stream that fails to parse is treated as malicious rather than clean — the opcodes before the break would already have executed in a real pickle.loads. That is the nullifAI evasion signature.',
        threshold: 'any GLOBAL outside the allowlist → SUSPICIOUS; any critical symbol or broken stream → MALICIOUS',
        reference: 'ReversingLabs nullifAI disclosure, February 2025; CWE-502',
      },
      {
        name: 'Structural reconstruction',
        basis: 'torch.load with weights_only=True as a second control, then a strict state-dict reconstruction. The input resolution is probed by measuring prediction entropy across candidate sizes rather than inferred from the stem kernel, because a 7×7 stem on a CIFAR-trained model points at 224 and every prediction saturates there.',
        threshold: 'analysis resolution capped at 96; strict=True only',
      },
      {
        name: 'Trigger inversion',
        basis: 'Per-class optimisation of a sigmoid-parameterised mask and pattern, then MAD normalisation of the recovered L1 norms. A backdoored class needs a dramatically smaller universal perturbation than every other class; the L1 ratio to the across-class median is the stable statistic and gets its own decisive band, because the anomaly index is a MAD normalisation over as few as ten values.',
        threshold: 'attack success ≥ 0.85 AND (L1 ratio ≤ 0.35 OR (anomaly index > 2.0 AND L1 ratio ≤ 0.55))',
        reference: 'Wang et al., Neural Cleanse, IEEE S&P 2019',
      },
      {
        name: 'Behavioural battery',
        basis: 'Nine synthetic probes — four corner patches, blended overlays, a sinusoidal pattern and a single-pixel stamp — applied over 1/f pink-noise references whose spectrum matches natural imagery. Scoring is on flip concentration and lift over the clean baseline, not the flip rate: a model that already predicts one class for everything flips at 100% and means nothing.',
        threshold: 'flip ≥ 0.50 AND concentration ≥ 0.85 AND lift ≥ 3.0×; baseline declared degenerate below 1.0 bits of entropy',
        reference: 'MITRE ATLAS AML.T0010',
      },
      {
        name: 'Weight statistics',
        basis: 'NaN and Inf sweeps, dead-tensor detection, outlier-neuron scoring by modified z-score, and spectral-norm ratios across layers.',
        threshold: 'modified z > 8 for an outlier neuron row',
      },
    ],
    gaps: [
      'A CRITICAL model verdict requires Neural Cleanse and the behavioural battery to agree on the same target class. Corroboration from one detector alone caps the verdict at HIGH, because each has a known false-positive mode and they are not the same mode.',
      'A checkpoint that fails the opcode audit is never deserialised. That is the correct trade: it means the behavioural verdict on a malicious file is BLACK_BOX and says so, rather than being obtained by running the attacker\'s code.',
      'Architectures the reconstructor does not recognise fall back to a grey-box assessment. Serialisation and weight statistics still run; trigger inversion does not.',
    ],
  },
  {
    id: 'inference',
    title: 'Inference provenance',
    icon: <Fingerprint size={15} />,
    lede: 'A record binds the input digest, the model digest, the preprocessing configuration, the prediction, the timestamp and a single-use nonce into one canonical document. Changing any of them changes the digest.',
    detectors: [
      {
        name: 'Canonicalisation',
        basis: 'RFC 8785 JSON Canonicalization Scheme, implemented independently in TypeScript and in Python and held to a shared vector file so the two can never drift. A digest that depends on key ordering is not a digest.',
        threshold: '13 shared test vectors, asserted in both test suites',
        reference: 'RFC 8785',
      },
      {
        name: 'Signature',
        basis: 'Ed25519 over the canonical bytes with domain separation, using one keyring shared by the gateway and the engine. The private half never leaves a 0600 file outside the web root.',
        threshold: 'RFC 8032 Ed25519',
      },
      {
        name: 'Replay defence',
        basis: 'A nonce ledger with a UNIQUE constraint. Re-presenting a consumed nonce is refused and classified — NONCE_REUSE for an identical resubmission, SUBSTITUTION when the payload differs.',
        threshold: 'one use per nonce, enforced by the database',
      },
      {
        name: 'Verdict separation',
        basis: 'VERIFIED, TAMPERED, FORGED and REPLAYED are four distinct outcomes. FORGED is the one that justifies the signature: the digest matches but the signature does not, which is what happens when someone recomputes the hash without holding the key. A hash-only scheme reports that case as clean.',
        threshold: 'digest equality and signature validity evaluated separately',
      },
    ],
  },
  {
    id: 'shift',
    title: 'Distribution shift',
    icon: <Waves size={15} />,
    lede: 'Two questions kept deliberately apart: has the operational distribution moved, and — if it has — is the movement weather or an attack?',
    detectors: [
      {
        name: 'Movement',
        basis: 'Maximum Mean Discrepancy under an RBF kernel with the bandwidth set by the median heuristic, and significance established by a permutation test. MMD is used rather than per-feature tests because covariate shift in imagery is a joint phenomenon: sensor gain, weather and terrain move several axes together.',
        threshold: 'MMD bands at 0.05 / 0.15 / 0.30; permutation α = 0.01',
        reference: 'Gretton et al., JMLR 2012',
      },
      {
        name: 'Attribution',
        basis: 'Two signals. Concentration: each target sample is scored by how far its kernel affinity to the baseline falls short, and the Gini coefficient of that deficit separates a whole batch moving a little (environment) from a few samples moving a lot (injection). Explainability: the photometric axes are projected out and MMD is re-measured — if the shift collapses, it was illumination.',
        threshold: 'HIGH reserved for shift that is both significant and unexplained',
      },
    ],
    gaps: [
      'Telling an operator that nightfall is an attack is the fastest way to lose their trust, so a diffuse, photometrically-explained shift is reported as environmental drift even when it is large and statistically significant.',
      'Attribution needs named feature axes to know which are photometric. Unnamed embedding dimensions still yield an MMD verdict, but the explainability half degrades to INSUFFICIENT_EVIDENCE.',
    ],
  },
  {
    id: 'governance',
    title: 'Risk and governance',
    icon: <Gavel size={15} />,
    lede: 'Composite risk is a weighted sum, but the decision is not. Override rules are evaluated before the bands, so a single critical finding cannot be averaged away by three clean components.',
    detectors: [
      {
        name: 'Composite risk',
        basis: 'Dataset 0.35, model 0.35, inference integrity 0.15, distribution shift 0.15. Label-noise risk is capped differently depending on whether the flips were systematic (25.0) or diffuse (8.0), because the two mean different things about intent.',
        threshold: 'ACCEPT below 30 · REVIEW 30–69 · QUARANTINE at or above 70',
      },
      {
        name: 'Override rules',
        basis: 'A malicious serialisation verdict, a corroborated backdoor, a broken audit chain or a tampered inference record each force QUARANTINE regardless of the arithmetic. The triggered rules are named in the report rather than folded into the score.',
        threshold: 'evaluated before the bands, never after',
      },
      {
        name: 'Audit ledger',
        basis: 'Every analysis, seal, verification and decision appends a hash-chained, Ed25519-signed block. UPDATE and DELETE are refused by SQLite trigger, not by convention. Verification fails closed on a malformed hash, a sequence gap or a signature mismatch.',
        threshold: 'chain verified end to end on every boot',
      },
    ],
  },
];

const SECURITY_CONTROLS = [
  { control: 'Session', detail: 'httpOnly __Host- cookie, SameSite=Strict, double-submit CSRF token held in memory only — never in localStorage, where any injected script can read it.' },
  { control: 'Credentials', detail: 'scrypt at N = 2^17 with the parameters stored alongside the hash, so the cost can be raised later without invalidating existing accounts.' },
  { control: 'Authorisation', detail: 'Explicit per-role capability grants. The console hides what a session cannot do; the server refuses it independently.' },
  { control: 'Transport', detail: 'Same-origin only. The gateway will open a socket to a loopback or RFC 1918 address and nothing else; a refusal is written to the ledger.' },
  { control: 'Content policy', detail: 'Nonce-based CSP, default-src self, frame-ancestors none. No CDN, font host, analytics or error-reporting endpoint is contacted.' },
  { control: 'Uploads', detail: 'Held in memory, size-capped, never written to disk under a caller-supplied name. The arbitrary-file-read endpoint that existed in the earlier build is gone.' },
  { control: 'Rate limiting', detail: 'Token bucket scoped to the API and analysis paths, keyed on a client address that only honours X-Forwarded-For for a declared number of proxy hops.' },
  { control: 'Error handling', detail: 'Exceptions return an incident identifier. Stack traces, paths and query text stay in the structured log, where sensitive keys are redacted.' },
];

export const MethodologyPage: React.FC = () => {
  const [active, setActive] = useState(SECTIONS[0].id);
  const containerRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: containerRef, offset: ['start start', 'end end'] });
  const glowY = useTransform(scrollYProgress, [0, 1], ['-10%', '110%']);

  // Highlight the section the reader is actually looking at.
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible) setActive(visible.target.id);
      },
      { rootMargin: '-25% 0px -60% 0px', threshold: [0.1, 0.4, 0.8] }
    );
    SECTIONS.forEach((section) => {
      const element = document.getElementById(section.id);
      if (element) observer.observe(element);
    });
    return () => observer.disconnect();
  }, []);

  return (
    /*
     * `overflow-clip`, not `overflow-hidden`: the decorative glow below is absolutely
     * positioned and travels past the end of this container, which would otherwise
     * extend the document and leave several hundred pixels of dead scroll under the
     * footer. `clip` trims it without creating a scroll container, so the sticky table
     * of contents still sticks to the viewport.
     */
    <div ref={containerRef} className="relative overflow-clip">
      {/* Parallax accent tied to reading progress, purely decorative and behind everything. */}
      <motion.div
        aria-hidden
        style={{ top: glowY }}
        className="pointer-events-none absolute -left-24 h-72 w-72 rounded-full bg-blue-600/8 blur-[90px]"
      />

      <div className="relative grid gap-5 lg:grid-cols-[210px_1fr]">
        <nav className="hidden lg:block">
          <div className="sticky top-24 space-y-1">
            <p className="mono mb-2 px-3 text-[9.5px] uppercase tracking-[0.16em] text-[var(--color-ink-dim)]">
              contents
            </p>
            {SECTIONS.map((section) => (
              <button
                key={section.id}
                onClick={() =>
                  document.getElementById(section.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
                }
                className={cn(
                  'relative flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-[12px] transition-colors',
                  active === section.id
                    ? 'text-[var(--color-ink)]'
                    : 'text-[var(--color-ink-dim)] hover:text-[var(--color-ink-muted)]'
                )}
              >
                {active === section.id && (
                  <motion.span
                    layoutId="methodology-active"
                    className="absolute inset-0 rounded-lg bg-white/6 ring-1 ring-inset ring-white/8"
                    transition={{ type: 'spring', stiffness: 380, damping: 32 }}
                  />
                )}
                <span className="relative text-[var(--color-accent-bright)]">{section.icon}</span>
                <span className="relative truncate">{section.title}</span>
              </button>
            ))}
            <button
              onClick={() =>
                document.getElementById('controls')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
              }
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-[12px] text-[var(--color-ink-dim)] transition-colors hover:text-[var(--color-ink-muted)]"
            >
              <span className="text-[var(--color-accent-bright)]">
                <ShieldAlert size={15} />
              </span>
              Security controls
            </button>
          </div>
        </nav>

        <div className="min-w-0 space-y-5">
          <Card tilt glow>
            <div className="p-6">
              <div className="flex items-start gap-4">
                <span className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl bg-blue-500/12 text-blue-300 ring-1 ring-inset ring-blue-500/25">
                  <BookOpen size={22} />
                </span>
                <div>
                  <h2 className="text-lg font-bold tracking-tight">How every verdict on this node is produced</h2>
                  <p className="mt-1.5 max-w-3xl text-[12.5px] leading-relaxed text-[var(--color-ink-muted)]">
                    Each detector below is named in the finding it produces, together with the exact
                    threshold that fired, so a reviewer can reproduce the decision without reading the
                    source. The thresholds quoted on this page are the constants that ship in the
                    engine configuration — not illustrative values.
                  </p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    <Badge tone="accent">SIH26228</Badge>
                    <Badge tone="neutral">air-gapped</Badge>
                    <Badge tone="neutral">RFC 8785</Badge>
                    <Badge tone="neutral">Ed25519</Badge>
                    <Badge tone="neutral">MITRE ATLAS</Badge>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {SECTIONS.map((section) => (
            <section key={section.id} id={section.id} className="scroll-mt-24">
              <Reveal>
                <Card>
                  <CardHeader title={section.title} subtitle={section.lede} icon={section.icon} />

                  <div className="space-y-px bg-[var(--color-border)] px-px">
                    {section.detectors.map((detector) => (
                      <div key={detector.name} className="bg-[var(--color-surface-1)] px-5 py-4">
                        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                          <p className="text-[12.5px] font-semibold">{detector.name}</p>
                          {detector.reference && (
                            <p className="mono text-[10px] text-[var(--color-ink-dim)]">{detector.reference}</p>
                          )}
                        </div>
                        <p className="mt-1.5 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                          {detector.basis}
                        </p>
                        <p className="mono mt-2 inline-flex items-start gap-1.5 rounded-lg bg-[var(--color-surface-0)]/70 px-2.5 py-1.5 text-[10.5px] leading-relaxed text-[var(--color-accent-bright)]">
                          <Braces size={11} className="mt-0.5 shrink-0" />
                          {detector.threshold}
                        </p>
                      </div>
                    ))}
                  </div>

                  {section.gaps && section.gaps.length > 0 && (
                    <div className="border-t border-amber-500/20 bg-amber-500/[0.04] px-5 py-4">
                      <p className="mono mb-2 flex items-center gap-1.5 text-[9.5px] uppercase tracking-wider text-amber-300">
                        <XCircle size={12} /> what this does not establish
                      </p>
                      <ul className="space-y-2">
                        {section.gaps.map((gap) => (
                          <li
                            key={gap}
                            className="flex gap-2 text-[11.5px] leading-relaxed text-amber-100/80"
                          >
                            <span className="shrink-0 text-amber-400/70">→</span>
                            {gap}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </Card>
              </Reveal>
            </section>
          ))}

          <section id="controls" className="scroll-mt-24">
            <Reveal>
              <Card>
                <CardHeader
                  title="Security controls"
                  subtitle="The console is itself part of the attack surface it assesses, so the controls are listed rather than assumed."
                  icon={<ShieldAlert size={15} />}
                />
                <div className="grid gap-px bg-[var(--color-border)] px-px pb-px sm:grid-cols-2">
                  {SECURITY_CONTROLS.map((entry) => (
                    <div key={entry.control} className="bg-[var(--color-surface-1)] px-5 py-3.5">
                      <p className="mono text-[10px] uppercase tracking-wider text-[var(--color-accent-bright)]">
                        {entry.control}
                      </p>
                      <p className="mt-1 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                        {entry.detail}
                      </p>
                    </div>
                  ))}
                </div>
              </Card>
            </Reveal>
          </section>

          <Reveal>
            <Card>
              <CardHeader
                title="Deliberately not claimed"
                subtitle="Capabilities this platform does not have, stated plainly so no one has to discover them during an assessment."
                icon={<Scale size={15} />}
              />
              <ul className="space-y-2.5 px-5 pb-5">
                {[
                  { icon: <Microscope size={13} />, text: 'No claim of certified detection. Every verdict carries a confidence and a coverage matrix; none of them is a guarantee.' },
                  { icon: <Binary size={13} />, text: 'No training, retraining or repair. This is an inspection layer. It never modifies a submitted asset and never produces a "cleaned" dataset.' },
                  { icon: <Boxes size={13} />, text: 'No formal verification of model behaviour. Trigger inversion and behavioural probing are empirical, bounded searches, and a sufficiently exotic trigger will survive both.' },
                  { icon: <Waves size={13} />, text: 'No runtime monitoring of a deployed model. The distribution-shift engine compares batches presented to it; it does not instrument inference in the field.' },
                  { icon: <Fingerprint size={13} />, text: 'Provenance proves a record was not altered after sealing. It cannot prove the prediction inside it was correct, or that the sealing host was itself uncompromised.' },
                ].map((row) => (
                  <li key={row.text} className="flex gap-2.5 text-[11.5px] leading-relaxed text-[var(--color-ink-muted)]">
                    <span className="mt-0.5 shrink-0 text-[var(--color-ink-dim)]">{row.icon}</span>
                    {row.text}
                  </li>
                ))}
              </ul>
            </Card>
          </Reveal>
        </div>
      </div>
    </div>
  );
};
