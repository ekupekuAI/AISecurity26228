<p align="center">
  <img src="docs/banner.svg" alt="TrustVision — Computer-vision integrity assurance, verified offline" width="100%">
</p>

<p align="center">
  <a href="https://github.com/ekupekuAI/AISecurity26228/releases">
    <img src="docs/download-bar.svg" alt="Download the offline TrustVision Windows app from the Releases page" width="100%">
  </a>
</p>

<p align="center"><b>▶ Get the app:</b> download <code>TrustVision-Windows.zip</code> from the
<a href="https://github.com/ekupekuAI/AISecurity26228/releases">Releases</a> page, unzip it, and
double-click <code>TrustVision.vbs</code>. Runs fully offline, nothing to install.</p>

<p align="center">
  <img src="docs/team-patriots.svg" alt="Built by Team Patriots for Smart India Hackathon 2026, problem SIH26228" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SIH%202026-PS%20SIH26228-1f3a8a">
  <img src="https://img.shields.io/badge/MoD-Indian%20Army%20(DGIS)-475569">
  <img src="https://img.shields.io/badge/node-%E2%89%A5%2022.5-3b82f6">
  <img src="https://img.shields.io/badge/python-%E2%89%A5%203.10-6366f1">
  <img src="https://img.shields.io/badge/runs-fully%20offline-16a34a">
  <img src="https://img.shields.io/badge/windows%20app-zero%20install-0ea5e9">
</p>

# TrustVision

**Trustworthy Computer-Vision Integrity Assurance for Data, Models and Inference Outputs**

TrustVision checks one thing that is hard to answer: **can you trust this computer-vision
pipeline?** Not just the model file, but the **data** it learned from, the **model** itself, and the
**predictions** it makes. You hand it an asset, it runs a full set of checks, and it gives you one
clear answer — with all the proof written to a log that cannot be edited.

---

## The problem

<p align="center">
  <img src="docs/problem.svg" alt="The problem: a vision pipeline is a supply chain that can be attacked; TrustVision inspects every link and proves the result" width="100%">
</p>

Defence vision systems get their data from many outside contributors, use models from third-party
vendors, and send live results to decision-makers. Any link can be poisoned. **SIH26228** asks for a
single, offline software layer that inspects the data, the model, and the inference output, ties them
together with cryptography, and gives an evidence-backed decision with a full audit trail.

---

## How it works

<p align="center">
  <img src="docs/workflow.svg" alt="Workflow: upload, inspect, findings and risk, verdict, signed passport, all recorded in the tamper-proof audit log" width="100%">
</p>

You sign in, upload a dataset or a model, and the checks run in the **background** while the screen
shows a live timer — so a big file never looks frozen. When it finishes you get findings, a risk
score, and a verdict, and you can export a signed passport. Every step is written to the audit log.

---

## The decision

<p align="center">
  <img src="docs/verdict.svg" alt="Three verdicts: ACCEPT below 30, REVIEW 30 to 69, QUARANTINE 70 and up" width="100%">
</p>

Thresholds are fixed by the problem statement. Two rules keep it honest: the decision is **per-asset**
(a bad model next to a clean dataset can't drag the clean one down), and there is **no silent
downgrade** — if a check could not run, the result is capped at REVIEW and says so. A gap is never an
ACCEPT.

---

## What it checks — the five engines

<p align="center">
  <img src="docs/engines.svg" alt="Five engines: dataset, model, inference, distribution shift, and governance with audit" width="100%">
</p>

### 1 · Dataset integrity

| Threat | Method |
|---|---|
| Exact duplicate flooding | Byte-identical grouping by SHA-256 |
| Near-duplicate flooding | Perceptual hash (pHash) + BK-tree search, confirmed by ResNet-18 embedding cosine > 0.98 |
| Flipped / systematic mislabelling | k-nearest-neighbour cross-check in feature space |
| Backdoor triggers | Residual clustering; recovers and **shows the actual trigger patch** |
| Out-of-distribution samples | Mahalanobis distance to class centroids |
| Corrupt files | Real decode check + magic-byte vs extension; COCO/YOLO schema checks |
| Unsafe archives | Zip-Slip, decompression bombs, symlink escape — caught before extraction |
| Bad contributors | Every defect rolled up to a per-source risk score |

### 2 · Model integrity

| Threat | Method |
|---|---|
| Malicious pickle | Reads the pickle opcodes **without running them**; fails closed on a broken stream (the nullifAI trick) |
| Structural trojans | ONNX graph inspection (built-in protobuf reader, works without the `onnx` package) |
| Weight anomalies | NaN/Inf, dead tensors, outlier neurons |
| Backdoors, by behaviour | A battery of trigger stamps, scored on how consistently they push inputs to one class (PyTorch and ONNX) |
| Backdoors, by inversion | Neural Cleanse trigger search — used only to **confirm** the behavioural result |

Every model result also states how deeply it could look: `WHITE_BOX`, `GREY_BOX`, `BLACK_BOX`, or `REFUSED`.

### 3 · Inference provenance

Binds the input hash, model hash, preprocessing config, prediction, timestamp, and a nonce into one
canonical record (RFC 8785), hashes it (SHA-256), and signs it (Ed25519). Verification returns
`VERIFIED`, `TAMPERED` (names the changed fields), `FORGED` (hash recomputed without the key), or
`REPLAYED`.

### 4 · Distribution shift

Maximum Mean Discrepancy (RBF kernel + permutation test), plus per-dimension KS and PSI. Normal drift
(weather, lighting, sensor) is separated from tampering by how concentrated the shift is and whether it
survives colour/contrast correction.

---

## Architecture

Two programs run on the same machine and talk only over `localhost`: a **Node/Express gateway** (the
console, database, and signed audit log) and a **Python engine** (all the real detectors). The engine
never listens beyond `localhost`, and the only outbound call in the system is the gateway reaching its
own local engine.

```mermaid
flowchart LR
    A["Browser console<br/>(React)"] -->|"session + CSRF"| B["Node gateway<br/>DB · roles · audit log"]
    B -->|"localhost only"| C["Python engine<br/>all detectors"]
    B --> L[("SQLite evidence DB<br/>hash-chained log")]
    B -. "engine off" .-> F["Degraded mode<br/>never ACCEPT"]
```

## The audit log

An append-only log in one SQLite database. Each entry stores the previous entry's hash and is signed
with Ed25519, so changing an old record breaks every record after it. Database triggers refuse UPDATE
and DELETE on the log, so even a compromised part of the app cannot rewrite history. It is
tamper-evident by design — not a blockchain, and not described as one.

## Keys and workspaces

Each operator gets a private workspace; their uploads and dashboard never mix with anyone else's. The
audit log and signing key are shared, which is what makes passports portable: a signed passport carries
its **own public key** inside the file, so any node can verify it offline. On first run the node
generates its keys into `data/keys/` and its session secret into `data/auth_secret.txt`; everything
you produce stays in the local `data/` folder.

---

## The pages

| Page | Purpose |
|---|---|
| Dashboard | Node verdict, risk pillars, open findings, recent log events |
| Dataset integrity | Duplicates, label issues, recovered triggers, OOD, contributors |
| Model integrity | Pickle audit, backdoor battery, Neural Cleanse, weight stats |
| Inference provenance | Seal a prediction, then tamper with it and watch verification catch it |
| Distribution shift | Compare a baseline image set against an operational one |
| Audit & reports | Read the log, verify the chain, generate a signed report |
| Model passport (AI-BOM) | Issue a passport; verify any pasted passport |
| Live monitoring (Sentinel) | Status board for the read-only sensor agents |
| Analytics | Risk trends and breakdown charts from this node's records |
| Settings / Methodology | Engine status, roles, password change; plain detector explainers |

---

## Does it catch things?

Scored against a labelled corpus built from real CIFAR-10 data with a genuinely fine-tuned backdoor
(99.99% attack success, 85.9% clean accuracy — high enough to pass ordinary validation).

| Asset | Ground truth | Verdict |
|---|---|---|
| `backdoored_model.pth` | BadNets corner trigger → class 0 | **DETECTED** → QUARANTINE |
| `clean_model.pth` | Clean, ~86% accuracy | Not a backdoor → ACCEPT |
| `malicious_model.pth` | `os.system` via pickle | **DETECTED**, risk 100, never deserialised |
| `nullifai_model.pth` | Payload behind a broken stream | **DETECTED**, risk 100 |
| `backdoored_model.onnx` | Same backdoor, ONNX | **DETECTED** via onnxruntime |
| `poisoned_corpus.zip` | 36 triggers, 34 floods, 28 flips | **DETECTED**, triggers recovered |
| `clean_corpus.zip` | Clean CIFAR-10 | ACCEPT |

Reproduce it: `python ml-engine/scripts/make_demo_assets.py`, then
`python -m pytest ml-engine/tests/test_ground_truth.py -v`.

---

## Technology stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Tailwind CSS v4, Radix UI, Motion, Recharts |
| Gateway | Node.js ≥ 22.5, Express, built-in `node:sqlite`, multer, zod |
| ML engine | Python ≥ 3.10, FastAPI + uvicorn, PyTorch + torchvision (CPU is enough), NumPy/SciPy/scikit-learn, Pillow, cryptography (Ed25519), onnx/onnxruntime |
| Build / test | Vite, esbuild, tsx, TypeScript, pytest |

Signing (Ed25519), hashing (SHA-256), password hashing (scrypt), and RFC 8785 canonicalisation use
Node's built-in `crypto` and Python's `cryptography`. No home-made cryptography.

---

## Running it

### Windows app (zero install, fully offline)

The whole system is packaged into one self-contained folder with its own Python + PyTorch and its own
Node runtime. It runs on any 64-bit Windows 10/11 machine with nothing to install and nothing touching
the internet.

1. Unzip `TrustVision-Windows.zip` anywhere, or build it (below).
2. Double-click `TrustVision.vbs`.
3. First launch only, Windows may say "Windows protected your PC" (the app is unsigned): **More info → Run anyway**.
4. The window opens in a few seconds. On the first run the analysis engine keeps loading in the
   background for a minute or two (PyTorch is large and your antivirus scans it once); you can sign in
   and look around straight away, and the top bar shows when analysis is ready.
5. Sign in as **`admin` / `TrustVision#2026`**, or use the no-password read-only session. Change the
   password in Settings.
6. To stop it, double-click `Stop TrustVision.vbs`.

Build the bundle from source:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\build-windows-app.ps1
```

### From source (development)

Needs Node.js 22.5+ and Python 3.10+.

```bash
npm install
python -m pip install -r ml-engine/requirements.txt
```

Stage the reference backbone once (needs network; then copy it to the offline node):

```bash
python ml-engine/scripts/provision_backbone.py
```

Start the engine, then the console, in two terminals:

```bash
npm run ml
npm run dev
```

Open <http://127.0.0.1:3000>. If you set `AIA_BOOTSTRAP_USER` / `AIA_BOOTSTRAP_PASSWORD`, those are
your admin login; otherwise the first boot prints a one-time password to the terminal. Create team
accounts with a gitignored `seed-users.json` (see `seed-users.example.json`) and `npm run seed:users`.

---

## Tests

```bash
npm test          # Node / gateway suite (73 tests)
npm run test:py   # Python engine suite (167 tests)
npm run verify    # typecheck plus both suites
```

---

## Limitations

- Does not detect clean-label poisoning (Poison Frogs, Sleeper Agent) or input-aware / warping
  backdoors (WaNet, BppAttack) from imagery — declared out of scope.
- Neural Cleanse only confirms the behavioural battery; it is not trusted on its own.
- The degraded fallback (engine off) is shallow by design and always capped at REVIEW.
- Single node — the audit log is one signed SQLite chain, not a distributed ledger.
- Authentication is local only: scrypt passwords and server-side sessions. No OAuth/SSO, no MFA.
- ONNX and safetensors get the behavioural battery but no gradient-based trigger inversion.

---

## Project layout

```
server/            Node gateway (db · security · provenance · routes)
ml-engine/         Python engine (security · vision · ingest · modelscan · provenance · analyzers)
src/               React 19 console
deploy/            Docker · systemd · windows/ (the zero-install app builder)
docs/              banner and section graphics
```

---

<p align="center">
  <img src="docs/team-patriots.svg" alt="Built by Team Patriots — Smart India Hackathon 2026, SIH26228" width="100%">
</p>

## References

- Gu et al., *BadNets* (2017); Chen et al., *Blended* (2017); Nguyen & Tran, *WaNet* (ICLR 2021)
- Wang et al., *Neural Cleanse* (IEEE S&P 2019); Tran et al., *Spectral Signatures* (2018)
- Lee et al., *Detecting OOD Samples* (NeurIPS 2018); Northcutt et al., *Confident Learning* (JAIR 2021)
- Gretton et al., *A Kernel Two-Sample Test* (JMLR 2012)
- RFC 8785 (JCS); RFC 8032 (Ed25519); CWE-502, CWE-22, CWE-409; MITRE ATLAS AML.T0010
