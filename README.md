<p align="center">
  <img src="docs/banner.svg" alt="TrustVision — AI supply-chain integrity, verified offline" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SIH%202026-PS%20SIH26228-1f3a8a">
  <img src="https://img.shields.io/badge/node-%E2%89%A5%2022.5-3b82f6">
  <img src="https://img.shields.io/badge/python-%E2%89%A5%203.10-6366f1">
  <img src="https://img.shields.io/badge/runs-fully%20offline-16a34a">
  <img src="https://img.shields.io/badge/deploy-single%20node%20/%20air--gapped-475569">
</p>

# TrustVision

**Smart India Hackathon 2026 · Problem SIH26228 · Ministry of Defence / Indian Army (DGIS)**

TrustVision is a tool for checking whether you can trust a computer-vision pipeline — the
**dataset** it learned from, the **model** file itself, and the **predictions** it produces.
You upload an asset, it runs a battery of checks, and it gives you one clear answer:
**ACCEPT, REVIEW, or QUARANTINE** — with the evidence behind it written to a tamper-proof log.

It's built to run on **one machine, with no internet** — because in a defence setting, the
thing you're inspecting might be hostile, and the inspector shouldn't be phoning home.

> One rule shapes the whole project: **"we didn't find a problem" and "we couldn't run the
> check" are not the same sentence.** Most tools blur the two. TrustVision always tells you
> which one it means, and a check it couldn't finish can never produce an ACCEPT.

---

## What it is, in one paragraph

Two programs run side by side on the same computer. A **Node/Express gateway** serves the
web console you log into, keeps the database, and holds the signed audit log. A **Python
engine** does the actual analysis — the deep-learning stuff, the cryptography, the image
math. They only ever talk to each other over `localhost`. You never expose the Python part
to the network. If the Python engine is off, the gateway still runs but drops to a stripped
"degraded" mode and says so on every screen — it will never quietly pretend a shallow check
was a deep one.

---

## The MVP

The minimum version that actually works and demonstrates the whole point:

> **Sign in → upload a dataset archive or a model file → the engine inspects it → you get an
> ACCEPT / REVIEW / QUARANTINE decision backed by findings → issue a signed passport for it →
> every step is recorded in a log you can't edit.**

Everything in this table is built and working today. Nothing here is a plan.

| Capability | What it does | Status |
|---|---|---|
| **Dataset inspection** | Finds duplicate-flooding, flipped labels, hidden backdoor triggers (and shows you the recovered trigger patch), out-of-distribution samples, corrupt files, and which contributor is responsible | ✅ Built |
| **Model inspection** | Reads a checkpoint *without running its pickle*, scans for backdoors two independent ways, checks the weights, and reports how deeply it could look (white-box / grey-box / black-box) | ✅ Built |
| **Inference provenance** | Seals a prediction into a signed record, then proves whether it was later tampered with, forged, or replayed | ✅ Built |
| **Distribution shift** | Compares two image sets and tells apart normal drift (lighting, weather) from deliberate manipulation | ✅ Built |
| **Governance decision** | Turns all of the above into ACCEPT / REVIEW / QUARANTINE with fixed thresholds and hard override rules | ✅ Built |
| **Tamper-proof audit log** | A hash-chained, signed, append-only ledger the database itself refuses to edit or delete | ✅ Built |
| **Signed passports (AI-BOM)** | Export a portable, signed `.aibom.json` for an analysed asset that anyone can verify offline | ✅ Built |
| **Multiple operators, separate workspaces** | Each user sees only their own uploads and dashboard; the log and passport verification stay shared | ✅ Built |

---

## How it's put together

```mermaid
flowchart TD
    A["Analyst in the browser<br/>React console"] -->|"cookie session + CSRF"| B["Node / Express gateway<br/>sessions · roles · SQLite · audit log"]
    B -->|"localhost only, SSRF-guarded"| C["Python engine (FastAPI)<br/>all the real detectors"]
    C --> D1["Dataset checks"]
    C --> D2["Model checks"]
    C --> D3["Inference sealing"]
    C --> D4["Distribution shift"]
    B --> L[("SQLite evidence DB<br/>hash-chained audit log")]
    B -. "engine unreachable" .-> F["Degraded fallback<br/>hashing + container scan only<br/>(can never ACCEPT)"]
```

The split is on purpose. The gateway owns everything durable and everything the browser
touches. The engine owns every judgement call and never listens beyond `localhost`. Nothing
in the system makes an outbound network request except the gateway calling the local engine —
and even that is locked to loopback/private addresses and re-checked on every call.

---

## What happens when you upload something

```mermaid
flowchart LR
    U["Upload dataset or model"] --> G["Gateway keeps the bytes in memory<br/>never written under your filename"]
    G --> E["Engine runs the detectors"]
    E --> Fnd["Findings + a risk score"]
    Fnd --> Gov{"Governance"}
    Gov -->|"low risk, nothing fatal"| Acc["ACCEPT"]
    Gov -->|"middling, or a check was skipped"| Rev["REVIEW"]
    Gov -->|"high risk, or a hard rule fired"| Qua["QUARANTINE"]
    Acc --> P["Issue a signed AI-BOM passport"]
    E --> Led[("Every step written to the audit log")]
```

---

## The five things it checks

### 1 · Datasets

| What we look for | How |
|---|---|
| Exact duplicate flooding | Group byte-identical images by SHA-256 |
| Near-duplicate flooding | Perceptual hash (pHash) + BK-tree search (Hamming ≤ 5), confirmed by ResNet-18 embedding cosine > 0.98 |
| Flipped labels | k-nearest-neighbour cross-check in feature space, with class-pair flow to tell targeted flipping from ordinary annotation noise |
| Backdoor triggers | Per-class and whole-corpus residual analysis with a statistical clustering test — and it recovers and **shows you the actual trigger patch** |
| Out-of-distribution samples | Mahalanobis distance to class centroids (Ledoit–Wolf shrunk covariance) |
| Corrupt / mislabelled files | Real decode check + magic-byte vs extension match; COCO/YOLO schema checks |
| Unsafe archives | Zip-Slip, decompression bombs, symlink escape — caught before extraction |
| Bad contributors | Rolls every defect up to a per-source risk score |

### 2 · Models

| What we look for | How |
|---|---|
| Malicious pickle | Disassembles the pickle opcodes **without executing them**, checks every import against an allowlist, and **fails closed** on a broken/truncated stream (the trick the Feb-2025 *nullifAI* samples used) |
| Structural trojans | ONNX graph inspection (works even without the `onnx` package, via a built-in protobuf reader) |
| Weight anomalies | NaN/Inf, dead tensors, outlier neurons, near rank-1 spectra |
| Backdoors (behaviour) | A battery of known trigger stamps run through the model; scored on how hard and how consistently they push inputs to one class. Works on PyTorch **and** on ONNX (via onnxruntime) |
| Backdoors (trigger inversion) | **Neural Cleanse** — optimises a mask/pattern per class. Used **only to corroborate** the behavioural battery, because on synthetic images it false-positives too often to be trusted alone. Not available for ONNX (no gradients), which we say out loud rather than skip silently |

Every model result also states its **access mode** — `WHITE_BOX`, `GREY_BOX`, `BLACK_BOX`, or
`REFUSED` — so a clean verdict always comes with "…and here's how deep we could actually see."

### 3 · Inference provenance

Binds the input hash, model hash, preprocessing config, prediction, timestamp, and a nonce
into one canonical document (RFC 8785), hashes it (SHA-256), and signs it (Ed25519). When you
verify later, you get one of four honest answers:

| Result | Meaning |
|---|---|
| `VERIFIED` | hash and signature both hold |
| `TAMPERED` | a bound field changed — it **names which fields** |
| `FORGED` | the hash matches but the signature doesn't — someone recomputed the hash without the key (a hash-only scheme would miss this) |
| `REPLAYED` | intact, but the nonce was already used, or the same input+model gave a different answer before |

### 4 · Distribution shift

Uses MMD (RBF kernel + permutation test), plus per-dimension KS and PSI on class priors. The
hard part the problem statement asks for — telling normal drift from tampering — is handled by
measuring how *concentrated* the shift is (a few samples moved a lot vs the whole batch moved a
little) and whether it disappears once you account for lighting/contrast/colour. HIGH severity
is reserved for shift that's both real and unexplained.

### 5 · Governance and the audit log

Covered in the next two sections.

---

## The decision: ACCEPT, REVIEW, or QUARANTINE

Thresholds are fixed by the problem statement: **ACCEPT below 30, REVIEW 30–69, QUARANTINE 70
and up.** But some conditions are fatal on their own and are checked *before* the score —
because averaging one catastrophic flaw against four healthy scores is exactly how a bad asset
gets waved through.

```mermaid
flowchart TD
    S["Analysis result"] --> O{"Any hard override?<br/>malicious pickle · confirmed backdoor<br/>tampered inference · unacknowledged CRITICAL"}
    O -->|yes| Q["QUARANTINE"]
    O -->|no| C{"Was any check skipped?<br/>engine down / scan didn't finish"}
    C -->|yes| R["REVIEW<br/>(a gap can never be ACCEPT)"]
    C -->|no| B{"Composite risk score"}
    B -->|"below 30"| A["ACCEPT"]
    B -->|"30 to 69"| R2["REVIEW"]
    B -->|"70 or more"| Q2["QUARANTINE"]
```

Two things worth calling out:

- **The decision is per-asset.** A malicious model uploaded next to a clean dataset can't drag
  the clean one down — each asset is judged on its own evidence.
- **No silent degradation.** If the Python engine is unreachable, the gateway runs a reduced
  fallback (hashing + container/pickle scan), records it in the audit log, shows a banner, and
  caps the verdict at REVIEW. A degraded run is a *gap*, never a clean bill of health.

---

## The audit log — "wait, is this a blockchain?"

Short answer: **no, and we won't call it one.** It's a hash-chained, signed, append-only log
in a single SQLite database. There's no peer-to-peer network, no consensus, no mining, no
second node agreeing with the first. Calling that a "blockchain" would be overselling it.

What it *is* is genuinely tamper-evident:

```mermaid
flowchart LR
    G["Genesis block"] --> B1["Block 1<br/>hash = H(previous + data)<br/>Ed25519 signed"]
    B1 --> B2["Block 2<br/>points back to Block 1's hash"]
    B2 --> B3["Block 3<br/>points back to Block 2's hash"]
    B3 --> V{{"Verify walks the whole chain<br/>any broken link fails, and names the block"}}
```

Each block includes the previous block's hash, so changing an old entry breaks every entry
after it. The database has triggers that **refuse UPDATE and DELETE** on the log table, so even
a compromised part of the app can't rewrite history. Verification is fail-closed: a missing
hash, a gap in the sequence, or a bad signature all count as a break, and it points at the
first block that failed.

---

## More than one person on one node

You can create several operator accounts and each gets their **own private workspace** — their
uploads, analyses, findings, and dashboard are theirs alone and never bleed into anyone else's.

What stays shared is deliberate: the **audit log** and the **signing key** are node-wide. That's
what makes signed passports portable — a passport one operator issues verifies for anyone,
because verification is pure cryptography against the key inside the passport, not a lookup in
that person's data.

Accounts come from the environment, never from the code. Point `AIA_SEED_USERS_FILE` at a JSON
file (kept out of git) and they're created on boot, or run `npm run seed:users`. Roles range
from a read-only observer up to a lead engineer, and each role has an explicit list of what it's
allowed to do.

---

## The pages

| Page | What it's for | What you upload |
|---|---|---|
| **Dashboard** | The node's overall verdict, risk pillars, open findings, recent log events | Nothing — it summarises |
| **Dataset integrity** | Inspect a dataset; see duplicates, label issues, recovered triggers, OOD, contributors | A dataset archive (`.zip`/`.tar`, COCO/YOLO/ImageFolder) or a single image |
| **Model integrity** | Inspect a checkpoint; pickle audit, backdoor battery, Neural Cleanse, weight stats | A model file (`.pt`, `.pth`, `.onnx`, `.ts`, `.safetensors`, `.bin`) |
| **Inference provenance** | Seal a prediction, then tamper with it in the "lab" and watch verification catch it | Nothing — you fill in form fields |
| **Distribution shift** | Compare a baseline image set against an operational one | Two sets of images (descriptors are computed in your browser; the images don't leave it) |
| **Audit & reports** | Read the log block by block, verify the chain, generate a signed report | Nothing |
| **Model passport (AI-BOM)** | Issue a signed passport from an analysis; verify any pasted passport | Paste passport JSON to verify (including one from another node) |
| **Live monitoring (Sentinel)** | Status board for the read-only sensor agents | Nothing |
| **Analytics** | Risk trends and breakdown charts from this node's own records | Nothing (empty node = empty charts, no fake data) |
| **Settings** | Engine endpoint, signing key info, roles, password change | Nothing |
| **Methodology** | Plain explainer of how each detector works | Nothing |

---

## Does it actually catch things? (ground truth)

The detectors are scored against a labelled corpus built from **real CIFAR-10** data with a
**genuinely fine-tuned backdoor** (99.99% attack success, 85.9% clean accuracy — good enough to
pass ordinary validation, which is what makes it dangerous). Accuracy is measured on the test
split the models never saw.

| Asset | Ground truth | Verdict |
|---|---|---|
| `backdoored_model.pth` | BadNets corner trigger → class 0 | **DETECTED** — the behavioural battery drives 99% of inputs to class 0 → QUARANTINE. Neural Cleanse only corroborates when it agrees on a class; here it doesn't independently flag, and we say so |
| `clean_model.pth` | clean, 86.6% accuracy | **not flagged as a backdoor** — risk 13.3, ACCEPT. Neural Cleanse raises an uncorroborated LOW *lead* on synthetic data — recorded for an analyst, never treated as a detection |
| `malicious_model.pth` | `os.system` via pickle | **DETECTED** — risk 100, never deserialised |
| `nullifai_model.pth` | payload + broken stream | **DETECTED** — risk 100 |
| `backdoored_model.onnx` | same backdoor, ONNX | **DETECTED** — behavioural battery via onnxruntime names class 0; trigger inversion declared unavailable (no gradients in ONNX) |
| `poisoned_corpus.zip` | 36 triggers, 34 floods, 28 flips | **DETECTED** — triggers recovered; the hostile contributor outranks the clean one |
| `clean_corpus.zip` | clean CIFAR-10 | ACCEPT — no trigger clusters |

Run it yourself: `python ml-engine/scripts/make_demo_assets.py`, then
`python -m pytest ml-engine/tests/test_ground_truth.py -v`.

> This suite exists because it once caught us out. An earlier build guessed a model's input
> size from its first layer; on these assets that flipped the results — a clean verdict on the
> real backdoor and a CRITICAL on the clean model. Every unit test still passed. Only a
> labelled corpus catches that kind of bug.

---

## Frameworks

Grouped by where it runs. Versions are exactly what's pinned in `package.json` and
`ml-engine/requirements.txt` (the Python side uses `>=` floors on purpose, so a security patch
can be applied without editing the file).

| Layer | Framework | Version | Role |
|---|---|---|---|
| **Frontend** | React + React DOM | 19.3.0 | The console UI |
| | Tailwind CSS (+ Vite plugin) | 4.1.14 | Styling |
| | Radix UI (dialog, tabs, tooltip, …) | 1.x–2.x | Accessible UI primitives |
| | Motion | ^12.23 | Animation |
| | Recharts | 3.10.1 | Analytics charts |
| | lucide-react | 0.546.0 | Icons |
| **Gateway** | Node.js | ≥ 22.5 | Runtime |
| | Express | 4.22.3 | HTTP server / routing |
| | `node:sqlite` | built-in | Embedded database (no native build step) |
| | multer | 2.4.0 | In-memory file uploads |
| | zod | 3.25.76 | Request validation |
| | dotenv | 17.4.2 | Config from `.env` |
| **ML engine** | Python | ≥ 3.10 | Runtime |
| | FastAPI + uvicorn | ≥ 0.115 / ≥ 0.30 | The analysis API |
| | PyTorch + torchvision | ≥ 2.2 / ≥ 0.17 | Backbone, behavioural battery, Neural Cleanse (CPU wheels are enough) |
| | NumPy / SciPy / scikit-learn | ≥ 1.26 / ≥ 1.11 / ≥ 1.4 | The detector math |
| | Pillow | ≥ 10.3 | Image decoding |
| | cryptography | ≥ 42 | Ed25519 signing |
| | onnx / onnxruntime | ≥ 1.16 / ≥ 1.18 | Optional — ONNX graph + behavioural checks |
| **Build / test** | Vite · esbuild · tsx · TypeScript | 6.4.3 · 0.25.12 · 4.21.0 · 5.8.3 | Dev server, bundling, TS runner, types |
| | pytest | ≥ 8 | Python tests |

Signing (Ed25519), hashing (SHA-256), password KDF (scrypt) and RFC 8785 canonicalisation use
Node's built-in `crypto` and Python's `cryptography` — no bespoke crypto.

---

## Run it locally

You need **Node.js 22.5+** and **Python 3.10+**.

```bash
npm install
```
```bash
python -m pip install -r ml-engine/requirements.txt
```

Stage the reference backbone once (needs network; ship the file to an offline node). Skip it
and embedding checks run in a weaker mode that says so — nothing breaks:

```bash
python ml-engine/scripts/provision_backbone.py
```

Start the engine first, then the console (two terminals):

```bash
npm run ml
```
```bash
npm run dev
```

Open <http://127.0.0.1:3000>. **The first boot prints a one-time admin password to the
terminal** — there is no default password. To create your team's accounts, put them in a
gitignored `seed-users.json` (see `seed-users.example.json`) and run:

```bash
npm run seed:users
```

Account recovery is deliberately a local, physical-access job (no network reset endpoint):

```bash
npx tsx scripts/admin.ts list
npx tsx scripts/admin.ts reset assurance.lead
```

---

## Tests

```bash
npm test          # Node/gateway suite (runs 70 tests in this build)
npm run test:py   # Python engine suite (150+ tests)
npm run verify    # typecheck + both suites in one pass
```

The Node suite covers canonicalisation, per-asset governance scoping, audit-chain
tamper-evidence, passport verification, persistence, and per-user isolation. The Python suite
covers the detectors, provenance, shift, security (pickle + archives), and the multipart
parser. Two heavier suites — the real gateway↔engine integration test and the CIFAR-10
ground-truth scoring — run when their prerequisites are present and skip cleanly otherwise
(start the engine, or generate the demo assets, to run them).

---

## Deploying it / sharing a link

Full walkthrough is in **[DEPLOY.md](DEPLOY.md)**. The short version:

- **The real deployment** is one hardened Docker container running both processes over
  loopback (`deploy/Dockerfile` + `deploy/docker-compose.yml`), or the same thing under systemd
  (`deploy/trustvision.service`). Read-only rootfs, all Linux capabilities dropped, evidence in
  a persistent volume.
- **To share a live link for testing**, put Caddy in front for automatic HTTPS on your domain
  (`deploy/docker-compose.public.yml`), or run a Cloudflare/ngrok tunnel to your machine.
- **A tunnel link only works while your machine and the app are running**, and a throwaway
  tunnel gives a new URL each time. A stable link that's up when your laptop is off needs a
  small always-on server (a cheap VM) plus a domain — that's the only setup that survives your
  machine being off.

This is **not a serverless app** and can't run on Vercel/Netlify — it needs a durable local
filesystem for the ledger, a private key on disk, a heavy Python engine, and multi-gigabyte
in-memory uploads. That's a design choice, not a gap.

---

## What it does *not* do

No sugar-coating. These are real boundaries, and most are called out in the app's own coverage
matrix:

- **It does not detect clean-label poisoning** (Poison Frogs, Sleeper Agent) or **input-aware /
  warping backdoors** (WaNet, BppAttack) from imagery. They're declared as out of scope, with
  the reason.
- **Neural Cleanse can't see all-to-all backdoors**, and on its own it isn't trusted — it only
  ever corroborates the behavioural battery.
- **The degraded fallback is genuinely shallow.** With the Python engine down you get hashing,
  container checks, and a basic pickle scan — no ML detectors. That result is always a coverage
  gap, never an ACCEPT.
- **It's a single node, not a distributed system.** The audit log is one signed SQLite chain,
  not a blockchain. There's no cross-node sync, no consensus, no SaaS control plane.
- **There is no packaged desktop app.** It runs as the web console + engine (or the Docker
  image). No `.exe`, no double-click installer today.
- **Auth is local only** — scrypt passwords and server-side sessions. No OAuth/SSO, no MFA, no
  email password reset.
- **ONNX and safetensors get no gradient-based trigger inversion** (only the behavioural
  battery, and only for ONNX). Full white-box certification needs a PyTorch checkpoint.

---

## Project layout

```
server/            Node gateway
  db/              schema · repositories · signed audit ledger
  security/        passwords · sessions · CSRF · roles · keyring · validation
  provenance/      RFC 8785 canonicalisation · sealing · verification
  routes/          auth · analysis · inference · governance · aibom · system
  analyzers/       degraded-mode fallback (clearly labelled)

ml-engine/         Python assurance engine
  security/        pickle opcode audit · archive guards
  vision/          imaging · phash · embeddings · duplicates · label noise · triggers · ood
  ingest/          COCO/YOLO parsers · contributor attribution
  modelscan/       torch · onnx · weight stats · behavioural battery · neural cleanse
  provenance/      canonicalisation · Ed25519 keyring · replay guard
  analyzers/       dataset · model · shift · risk · coverage
  scripts/         provision_backbone.py · make_demo_assets.py

src/               React 19 console (Tailwind v4, Radix, Motion, Recharts)
  components/pages/  dashboard · dataset · model · inference · shift · audit · passport · …
scripts/           seed-users.ts · admin.ts (local operator CLI)
deploy/            Dockerfile · docker-compose · Caddyfile · systemd unit
```

---

## References

- Gu et al., *BadNets* (2017) · Chen et al., *Blended* (2017) · Nguyen & Tran, *WaNet* (ICLR 2021)
- Wang et al., *Neural Cleanse* (IEEE S&P 2019) · Tran et al., *Spectral Signatures* (2018)
- Lee et al., *Detecting OOD Samples* (NeurIPS 2018) · Northcutt et al., *Confident Learning* (JAIR 2021)
- Gretton et al., *A Kernel Two-Sample Test* (JMLR 2012)
- RFC 8785 (JCS) · RFC 8032 (Ed25519) · CWE-502, CWE-22, CWE-409 · MITRE ATLAS AML.T0010
- ReversingLabs, *nullifAI* malicious ML models on Hugging Face (February 2025)
