# AI Integrity Assurance Platform

**SIH 2026 · PS SIH26228 · Ministry of Defence (MoD) / Indian Army (DGIS)**
*Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines*

An offline, air-gapped assurance and inspection layer for computer-vision supply chains.
It inspects a **dataset**, a **model** and an **inference stream** as zero-trust assets,
binds inference outputs cryptographically, quantifies distribution shift, and issues an
evidence-backed **ACCEPT / REVIEW / QUARANTINE** decision against a tamper-evident audit
ledger.

---

## What makes this different

Most assurance tooling reports what it found. This reports what it found **and what it
could not check** — because in a defence context, "no backdoor finding" and "we could not
run the model" are completely different statements, and conflating them is how a
compromised asset gets certified.

Three things follow from that principle:

1. **Every model assessment publishes its access mode** — `WHITE_BOX`, `GREY_BOX`,
   `BLACK_BOX` or `REFUSED` — so a clean verdict is always qualified by what was actually
   possible.
2. **Every engine publishes an attack-coverage matrix** naming the threats it does *not*
   cover (clean-label poisoning, WaNet-style input-aware backdoors) and why.
3. **A coverage gap can never yield ACCEPT.** If the assurance engine was unreachable, or
   trigger inversion did not finish, the governance engine returns REVIEW.

## Validated against ground truth

The detectors are scored against a labelled corpus built from **real CIFAR-10** data with
a **genuinely fine-tuned backdoor** (100% attack success rate, 85.8% clean accuracy — high
enough to pass ordinary validation, which is exactly what makes it dangerous).

| Asset | Ground truth | Platform verdict |
|---|---|---|
| `backdoored_model.pth` | BadNets corner trigger → class 0 | **DETECTED** · Neural Cleanse flags class **0** (L1 28-33% of the across-class median across runs, against a clean-model minimum of 61%) · battery confirms 99% flip rate, 100% concentration, 10× lift |
| `clean_model.pth` | clean, 94% accuracy | **NOT DETECTED** · zero backdoor confidence |
| `malicious_model.pth` | `os.system` via REDUCE | **DETECTED** · risk 100 · never deserialised |
| `nullifai_model.pth` | payload + broken stream | **DETECTED** · risk 100 |
| `poisoned_corpus.zip` | 36 triggers, 34 floods, 28 flips | **DETECTED** · 33/36 triggers recovered · hostile contributor scored 99.9 vs 41.9 |
| `clean_corpus.zip` | clean CIFAR-10 | risk **15.3** (ACCEPT band) · no trigger clusters |

Run it yourself: `python ml-engine/scripts/make_demo_assets.py` then
`python -m pytest ml-engine/tests/test_ground_truth.py -v`.

Inversion is a bounded stochastic search, so the exact figures move a little between
runs. The finding text names which condition actually fired — the decisive L1 ratio band,
the MAD anomaly index, or both — rather than asserting a fixed one, because the anomaly
index is normalised over as few as ten values and has landed on either side of its 2.0
threshold on consecutive runs of the same checkpoint.

> This suite exists because it caught a real inversion. An earlier build inferred a
> model's input resolution from its stem kernel; on these assets that produced a CRITICAL
> verdict on the clean model and a clean verdict on the 100%-ASR backdoor. Every unit test
> still passed. Only a labelled corpus catches that class of error.

---

## Architecture

```
                        ┌─────────────────────────────┐
                        │   ANALYST CONSOLE (React)   │
                        │   cookie session + CSRF     │
                        └──────────────┬──────────────┘
                                       │ same-origin REST
                        ┌──────────────▼──────────────┐
                        │   NODE GATEWAY (Express)    │
                        │  sessions · RBAC · SQLite   │
                        │  audit ledger · provenance  │
                        └──────────────┬──────────────┘
                                       │ loopback only, SSRF-constrained
                        ┌──────────────▼──────────────┐
                        │  ASSURANCE ENGINE (FastAPI) │
                        └──────────────┬──────────────┘
          ┌──────────────┬─────────────┼─────────────┬──────────────┐
          ▼              ▼             ▼             ▼              ▼
     ┌─────────┐   ┌─────────┐   ┌──────────┐  ┌─────────┐   ┌──────────┐
     │ DATASET │   │  MODEL  │   │INFERENCE │  │  SHIFT  │   │   RISK   │
     │ pHash   │   │ pickle  │   │ RFC 8785 │  │  MMD +  │   │ weighted │
     │ k-NN    │   │ audit   │   │ Ed25519  │  │ attrib- │   │ + over-  │
     │ triggers│   │ Neural  │   │ replay   │  │ ution   │   │ rides    │
     │ OOD     │   │ Cleanse │   │ guard    │  │         │   │          │
     └─────────┘   └─────────┘   └──────────┘  └─────────┘   └──────────┘
```

**Why the split.** The gateway owns sessions, durable evidence and the browser surface.
The engine owns every analytical decision and never listens beyond loopback. If the engine
is down the gateway degrades to hashing and container checks — and says so, loudly, in the
result.

---

## Quick start

**Prerequisites:** Node.js 22.5+, Python 3.10+

```bash
npm install
python -m pip install -r ml-engine/requirements.txt
```

Stage the reference feature backbone once (needs network; ship the file to air-gapped
nodes):

```bash
python ml-engine/scripts/provision_backbone.py
```

Start the engine, then the console:

```bash
python -m uvicorn app:app --app-dir ml-engine --host 127.0.0.1 --port 8000
npm run dev
```

Open <http://127.0.0.1:3000>. **First boot prints a one-time administrator credential to
the server console.** There is no default password. Set `AIA_BOOTSTRAP_USER` and
`AIA_BOOTSTRAP_PASSWORD` to control it.

### Accounts

There is no password-reset endpoint, by design: a reset route reachable over the network
is an authentication bypass waiting for one authorisation mistake. Recovery is a
physical-access operation through a local CLI, and every action it takes is written to the
audit ledger.

```bash
npx tsx scripts/admin.ts list
npx tsx scripts/admin.ts reset assurance.lead                 # generates and prints one
npx tsx scripts/admin.ts reset assurance.lead --password '<value>'
npx tsx scripts/admin.ts create inspector.one DEFENSE_INSPECTOR
npx tsx scripts/admin.ts disable inspector.one
```

A reset revokes every live session for that account and clears its lockout counter. A
supplied password is held to the same policy the console enforces (12+ characters, no
username fragment, no common term, no long sequential run).

### Production

```bash
npm run build
NODE_ENV=production AIA_DEMO_MODE=false AUTH_SECRET=<48+ random bytes> npm start
```

Production **refuses to start** if demo mode is enabled or the build is missing.

In production the session cookie is issued `Secure` with a `__Host-` prefix, so the
console **must be reached over https**. Put a TLS terminator in front of the node and set
`APP_URL=https://...`. Over plain http a browser silently discards the cookie, sign-in
returns 200 and the next request returns 401; the node warns about this at boot rather
than letting it look like a broken login.

### Where this can and cannot be deployed

This is a **single stateful node**, not a serverless web app, and that is a design
requirement rather than a limitation to engineer around:

| Requirement | Why it rules out a serverless platform |
|---|---|
| Append-only SQLite ledger with WAL | Needs a durable local filesystem that survives between requests. Serverless filesystems are ephemeral and per-invocation, so the hash chain would be lost or forked. |
| Ed25519 private key on a 0600 file | Must never leave the node. |
| Python engine with torch, torchvision, PIL | Hundreds of megabytes and 40-100 s of CPU for trigger inversion. Past every mainstream serverless bundle and timeout ceiling. |
| Multi-gigabyte uploads held in memory | Past serverless request-body limits. |
| Air-gap posture | The whole point is that the node has no route to the internet. |

**Vercel, Netlify and comparable platforms will not run this.** The React console alone
would deploy there, but it would be a shell with no engine, no database, no keyring and
no evidence — which is worse than not deploying it at all.

Deploy it the way it is meant to run: `deploy/Dockerfile` and `deploy/docker-compose.yml`
build a non-root, read-only-rootfs container with `cap_drop: ALL`, and
`deploy/aia-assurance.service` runs it under systemd on a hardened host. Both bind to
loopback; put a TLS terminator in front if the console is reached from another machine on
the same closed network.

---

## Capabilities

### 1 · Dataset integrity

| Threat | Method |
|---|---|
| Exact duplicate flooding | SHA-256 grouping |
| Near-duplicate flooding | DCT pHash + BK-tree radius query (Hamming ≤ 5), confirmed by ResNet-18 embedding cosine > 0.98 |
| Label flipping | k-NN clean-feature cross-validation with **directed class-pair flow analysis** to separate targeted flipping from diffuse annotation noise |
| Backdoor triggers | Per-class **and** whole-corpus median residual, spatial-coincidence clustering with a Bonferroni-corrected Poisson test, pattern-agreement and locality confirmation, then seed-and-grow expansion. **The recovered trigger pattern is returned as evidence.** |
| Out-of-distribution | Mahalanobis distance to class centroids with Ledoit–Wolf shrunk pooled covariance |
| Annotation manipulation | COCO JSON + YOLO schema conformance (dangling ids, undeclared categories, out-of-range boxes) |
| Archive supply chain | Zip Slip, decompression bombs, symlink escape, header-mismatch |
| Evaluation contamination | Duplicate clusters spanning train/test splits |
| Source attribution | Manifest / directory-hint / partition strategies → weighted defect **density** per contributor |

### 2 · Model integrity

| Threat | Method |
|---|---|
| Malicious deserialisation | Full `pickletools` opcode disassembly against a symbol allowlist. **Fails closed on a broken stream** and unwraps non-standard containers — the two evasions used by the Feb 2025 *nullifAI* Hugging Face samples. |
| Structural trojanisation | ONNX graph enumeration (operator allowlist, orphan nodes, custom domains) with a built-in protobuf walker when the `onnx` package is absent |
| Weight anomalies | NaN/Inf, dead tensors, per-channel outlier neurons, spectral ratio |
| Backdoor (trigger inversion) | **Neural Cleanse** per-class mask optimisation with MAD anomaly index **and** an L1-ratio requirement |
| Backdoor (behavioural) | Nine-battery trigger suite across four corner placements, scored on **flip concentration and lift over the clean baseline** |

Two independent detectors must agree on the **same target class** before a CRITICAL
backdoor verdict is issued. Trigger inversion alone yields a HIGH "requires adjudication"
lead, because it has a non-trivial false-positive rate at a bounded step budget.

The analysis resolution is chosen by **measuring** the model — prediction entropy across
candidate resolutions — not by guessing from the stem kernel.

### 3 · Inference provenance

Binds input digest + model digest + preprocessing configuration + prediction + timestamp +
nonce into one **RFC 8785 (JCS)** canonical document, SHA-256 hashed and **Ed25519**
signed. Verification distinguishes four outcomes:

| Status | Meaning |
|---|---|
| `VERIFIED` | digest and signature both hold |
| `TAMPERED` | a bound field changed — the altered fields are **named** |
| `FORGED` | digest matches but signature does not: someone recomputed the hash without the key. **A hash-only scheme cannot detect this.** |
| `REPLAYED` | intact but the nonce was consumed, or the same input+model previously produced a different answer |

Canonicalisation is implemented twice — TypeScript and Python — and pinned by a
[shared vector suite](server/provenance/vectors.json) so a record sealed by either process
verifies in the other.

### 4 · Distribution shift

MMD with an RBF kernel (median-heuristic bandwidth) and a permutation test, plus KS per
dimension and PSI on class priors.

The problem statement asks to *distinguish operational drift from suspicious
manipulation*, and that is treated as the harder half:

- **Concentration** — each sample's kernel-affinity deficit against the baseline, measured
  by Gini. Dusk moves the whole batch a little; injection moves a few samples a lot.
- **Photometric explainability** — projecting out luminance/contrast/colour axes. If the
  discrepancy collapses, it *is* an illumination change.

HIGH severity is reserved for shift that is both significant **and** unexplained.

### 5 · Governance and audit

Thresholds fixed by the problem statement: **ACCEPT < 30 · REVIEW 30–69 · QUARANTINE ≥ 70**.

Override conditions are evaluated **before** the score — a cryptographic tamper, confirmed
backdoor, malicious checkpoint or replay quarantines regardless of the composite, because
averaging a fatal defect against four healthy pillars is how a real failure ships.

The audit ledger is hash-chained, Ed25519-signed, and **append-only enforced by SQLite
triggers**. Verification fails closed: a missing hash, a sequence gap or a signature
mismatch is a break, and the first broken block is named.

---

## Security posture

This build fixed several exploitable defects in its predecessor. They are listed because
the fixes are the substance of the work:

| Defect | Status |
|---|---|
| `POST /api/auth/quick-role` minted an unauthenticated `LEVEL_4_TOP_SECRET` admin token | **Removed.** Replaced by a demo-mode-only read-only observer with no write capability. |
| Frontend auto-logged-in as Level 4 and fabricated a user when the backend refused | **Removed.** Real sign-in screen; the server is the only source of identity. |
| `POST /api/demo/load-real-fixture` read any path from the request body | **Endpoint deleted.** |
| ML engine URL settable to any host → exfiltration of every upload | **Loopback/private-range allowlist**, re-validated per call, refusals audited. |
| Zip entries expanded with no size or ratio ceiling | **Four-way bomb guard** in both the engine and the gateway. |
| Rate limiter trusted `X-Forwarded-For` unconditionally | **Only honoured behind a declared proxy hop count.** |
| Audit hash covered only some columns; verification passed on a blank hash | **Covers every field, signed, fails closed.** |
| Session token in `localStorage` | **httpOnly `__Host-` cookie + double-submit CSRF.** |
| CSP allowed `unsafe-eval` and `frame-ancestors *` | **Nonce-based CSP, `frame-ancestors 'none'`, HSTS.** |
| Raw exception messages returned to clients | **Incident id only**; the message is logged. |
| Mutating "sanitiser" silently corrupted request bodies | **Replaced by strict schema validation** that rejects. |
| Google Fonts fetched from the internet; `firebase` dependency with a live API key; `SERVER_SIDE_GEMINI_API` capability | **All removed.** Fonts vendored; zero external origins in the build. |

Other controls: scrypt (N=2^17) with stored parameters and rehash-on-login, account
lockout with exponential backoff, per-role capability grants, idle + absolute session
timeouts, SSRF-safe engine client that refuses redirects, `PRAGMA foreign_keys`/`WAL`/
`synchronous=FULL`, and structured logs with automatic secret redaction.

---

## PRD compliance

| Requirement | Status | Where |
|---|---|---|
| pHash, Hamming ≤ 5, cosine > 0.98 | ✅ | `vision/phash.py`, `vision/duplicates.py` |
| Label flipping via k-NN discordance | ✅ | `vision/label_noise.py` |
| Trigger detection with bounding box | ✅ + recovered pattern | `vision/triggers.py` |
| OOD via Mahalanobis to class centroids | ✅ | `vision/ood.py` |
| Contributor risk aggregation | ✅ | `ingest/contributors.py` |
| COCO JSON / YOLO / ImageFolder | ✅ | `ingest/parsers.py` |
| ONNX graph + PyTorch state-dict audit | ✅ | `modelscan/onnx_inspect.py`, `torch_inspect.py` |
| Neural Cleanse trigger inversion | ✅ | `modelscan/neural_cleanse.py` |
| Behavioural reference battery | ✅ | `modelscan/battery.py` |
| Capability & limitation disclosure | ✅ | `analyzers/coverage.py` |
| Canonical record + SHA-256 + signature | ✅ Ed25519 | `provenance/` |
| Replay / substitution prevention | ✅ | `provenance/records.py`, `nonces` table |
| MMD distribution shift | ✅ + drift attribution | `analyzers/shift_analyzer.py` |
| ACCEPT/REVIEW/QUARANTINE at 30/70 | ✅ | `analyzers/risk_engine.py` |
| Hash-chained audit trail | ✅ + Ed25519 + append-only triggers | `server/db/audit.ts` |
| Schema: assets, datasets, models, findings, inference_records, audit_events | ✅ + contributors, nonces | `server/db/schema.ts` |
| Air-gapped, zero external calls | ✅ | verified in `dist/` |

**Deliberately not claimed:** clean-label poisoning (Poison Frogs, Sleeper Agent) and
input-aware backdoors (WaNet, BppAttack) are **not** detected from imagery. Both are
declared in the coverage matrix with the reason. Neural Cleanse cannot see all-to-all
backdoors. The behavioural battery measures trigger *responsiveness* on synthetic inputs,
not mission accuracy.

---

## Verification

```bash
npm run typecheck    # 0 errors, strict mode
npm test             # canonicalisation conformance vs the shared vectors
npm run build        # production bundle
python -m pytest ml-engine/tests -q        # 145 tests
python -m pytest ml-engine/tests/test_ground_truth.py -v   # labelled-corpus scoring
```

---

## Layout

```
server/            Node gateway
  config.ts        fail-fast config, SSRF allowlist
  db/              schema · repositories · signed audit ledger
  security/        passwords · sessions · CSRF · RBAC · keyring · validation
  provenance/      RFC 8785 canonicalisation · sealing · verification
  routes/          auth · analysis · inference · governance · system
  analyzers/       degraded-mode fallbacks (clearly labelled)

ml-engine/         Python assurance engine
  security/        pickle opcode audit · archive guards
  vision/          imaging · phash · embeddings · duplicates · label noise · triggers · ood
  ingest/          COCO/YOLO parsers · contributor attribution
  modelscan/       torch · onnx · weight stats · battery · neural cleanse
  provenance/      canonicalisation · Ed25519 keyring · replay guard
  analyzers/       dataset · model · shift · risk · coverage
  scripts/         provision_backbone.py · make_demo_assets.py

src/               React 19 console -- Tailwind v4, Radix primitives, Motion, Recharts
  ui/              design-system primitives (button, card, badge, risk bar, toasts)
  components/      shell, login, finding inspector
    pages/         dashboard - dataset - model - inference - shift - audit - config - methodology
  api/             typed REST client (httpOnly cookie + in-memory CSRF token)
scripts/admin.ts   local operator CLI for account recovery
```

## References

- Gu et al., *BadNets* (2017) · Chen et al., *Blended* (2017) · Nguyen & Tran, *WaNet* (ICLR 2021)
- Wang et al., *Neural Cleanse* (IEEE S&P 2019) · Tran et al., *Spectral Signatures* (2018)
- Lee et al., *A Simple Unified Framework for Detecting OOD Samples* (NeurIPS 2018)
- Northcutt et al., *Confident Learning* (JAIR 2021) · Gretton et al., *A Kernel Two-Sample Test* (JMLR 2012)
- RFC 8785 (JCS) · RFC 8032 (Ed25519) · CWE-502, CWE-22, CWE-409 · MITRE ATLAS AML.T0010
- ReversingLabs, *nullifAI* malicious ML models on Hugging Face (February 2025)
