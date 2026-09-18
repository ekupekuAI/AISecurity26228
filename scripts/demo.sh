#!/usr/bin/env bash
#
# End-to-end walkthrough of the assurance workflow against a running node.
#
#   bash scripts/demo.sh [base-url]
#
# Requires the evaluation corpus:  python ml-engine/scripts/make_demo_assets.py
#
# Everything this prints is produced by the platform at run time. No result is
# pre-recorded: the backdoor is found by trigger inversion, the tamper is caught by
# recomputing a digest, and the ledger is verified block by block.
set -uo pipefail

BASE="${1:-http://127.0.0.1:3000}"
JAR="$(mktemp -t aia-cookies.XXXXXX)"
USER_ID="${AIA_BOOTSTRAP_USER:-assurance.lead}"
PASSWORD="${AIA_BOOTSTRAP_PASSWORD:?set AIA_BOOTSTRAP_PASSWORD to the console credential}"
ASSETS="demo-assets"

trap 'rm -f "$JAR"' EXIT

rule()    { printf '\n\033[1;34m%s\033[0m\n' "$(printf '=%.0s' {1..76})"; }
step()    { rule; printf '\033[1;34m  %s\033[0m\n' "$1"; rule; }
jq_py()   { python -c "import json,sys$(printf '\n%s' "$1")"; }

if [ ! -d "$ASSETS" ]; then
  echo "Evaluation corpus not found. Run: python ml-engine/scripts/make_demo_assets.py" >&2
  exit 1
fi

step "0  Authenticate"
LOGIN=$(curl -sS -c "$JAR" -X POST "$BASE/api/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"identifier\":\"$USER_ID\",\"password\":\"$PASSWORD\"}")
CSRF=$(printf '%s' "$LOGIN" | jq_py "
d=json.load(sys.stdin)
print(d.get('csrfToken',''))")

if [ -z "$CSRF" ]; then
  echo "Sign-in failed: $LOGIN" >&2
  exit 1
fi
printf '%s' "$LOGIN" | jq_py "
d=json.load(sys.stdin)['user']
print(f\"  {d['name']} - {d['role']} ({d['clearanceLevel']})\")
print(f\"  capabilities: {', '.join(d['capabilities'])}\")"

AUTH=(-b "$JAR" -H "x-aia-csrf: $CSRF")

step "1  Hostile checkpoint -- refused without deserialisation"
for model in malicious_model.pth nullifai_model.pth; do
  curl -sS "${AUTH[@]}" -F "file=@$ASSETS/$model" "$BASE/api/analyze/model" | jq_py "
d=json.load(sys.stdin)
print(f\"  {d['filename']}\")
print(f\"    verdict      : {d['status']}  risk {d['modelRisk']}  access {d['analysisMode']}\")
a=d.get('pickleAudit') or {}
print(f\"    opcode audit : {a.get('verdict')}  container {a.get('container')}\")
crit=[g['qualname'] for g in a.get('criticalGlobals',[])]
print(f\"    primitives   : {', '.join(crit) if crit else 'none'}\")
print(f\"    deserialised : {d.get('torchInspection') is not None}\")
for f in d['findings']: print(f\"    [{f['severity']}] {f['findingId']}\")"
done

step "2  Backdoored checkpoint -- trigger inversion (this takes ~1 min)"
curl -sS "${AUTH[@]}" -F "file=@$ASSETS/backdoored_model.pth" "$BASE/api/analyze/model" | jq_py "
d=json.load(sys.stdin)
print(f\"  {d['filename']}\")
print(f\"    architecture : {d['architecture']}\")
print(f\"    parameters   : {d['parameterCount']:,}\")
print(f\"    access mode  : {d['analysisMode']}\")
print(f\"    verdict      : {d['status']}  risk {d['modelRisk']}  backdoor confidence {d['backdoorConfidence']:.0%}\")
nc=d.get('neuralCleanse') or {}
if nc.get('ran'):
    print(f\"    Neural Cleanse: flagged class(es) {nc['flaggedClasses']}  max anomaly index {nc['maxAnomalyIndex']:.2f} (threshold {nc['anomalyIndexThreshold']})\")
    for i in nc['inversions']:
        mark='  <== FLAGGED' if i['flagged'] else ''
        print(f\"      class {i['classIndex']}: L1 {i['l1Norm']:7.1f}  {i['l1RatioToMedian']:.0%} of median  ASR {i['attackSuccessRate']:.0%}{mark}\")
bb=d.get('behaviouralBattery') or {}
if bb.get('ran'):
    print(f\"    Battery: baseline entropy {bb['cleanPredictionEntropy']:.2f} bits at {bb['inputShape']}\")
    for b in bb['batteries']:
        if b['verdict'] in ('STRONG_BACKDOOR_INDICATION','SUSPICIOUS'):
            print(f\"      {b['name']}: flip {b['flipRate']:.0%}  concentration {b['flipConcentration']:.0%}  lift {b['liftOverBaseline']:.1f}x  -> class {b['targetClass']}  {b['verdict']}\")
for f in d['findings']: print(f\"    [{f['severity']}] {f['findingId']}\")
print(f\"    limitations  : {d['limitations'][:160]}...\")"

step "3  Clean checkpoint -- negative control"
curl -sS "${AUTH[@]}" -F "file=@$ASSETS/clean_model.pth" "$BASE/api/analyze/model" | jq_py "
d=json.load(sys.stdin)
nc=d.get('neuralCleanse') or {}
print(f\"  {d['filename']}\")
print(f\"    verdict      : {d['status']}  risk {d['modelRisk']}  backdoor confidence {d['backdoorConfidence']:.0%}\")
print(f\"    flagged      : {nc.get('flaggedClasses')}  (a clean model must produce none)\")"

step "4  Poisoned corpus -- three simultaneous attacks"
curl -sS "${AUTH[@]}" -F "file=@$ASSETS/poisoned_corpus.zip" "$BASE/api/analyze/dataset" | jq_py "
d=json.load(sys.stdin)
print(f\"  {d['filename']}  ({d['totalSamples']} samples, format {d['format']})\")
print(f\"    verdict: {d['status']}  risk {d['datasetRisk']}\")
t=d.get('triggerAnalysis') or {}
for c in t.get('clusters',[]):
    print(f\"    TRIGGER  class '{c['label']}': {c['memberCount']} samples at bbox {c['bbox']}\")
    print(f\"             p={c['familyWisePValue']:.1e}  consistency {c['spatialConsistency']:.2f}  via {c['referenceFrame']}\")
    print(f\"             family: {c['suspectedFamily']}\")
    print(f\"             recovered trigger pattern returned as {len(c['recoveredTriggerPatch'])}x{len(c['recoveredTriggerPatch'][0])} RGB evidence\")
du=d.get('duplicateAnalysis') or {}
print(f\"    DUPLICATES: {du.get('totalRedundantSamples')} redundant ({du.get('exactDuplicateSamples')} exact, {du.get('nearDuplicateSamples')} perceptual)\")
la=d.get('labelAnalysis') or {}
if la.get('suspectCount'): print(f\"    LABELS   : {la['suspectCount']} suspect, systematic={la['systematicManipulation']}\")
print('    CONTRIBUTOR ATTRIBUTION:')
for p in d.get('contributorProfiles',[]):
    print(f\"      {p['name']:22s} risk {p['riskScore']:5.1f}/100  {p['sampleCount']:4d} samples  {p['triggerSamples']:3d} triggered\")
    for driver in p.get('riskDrivers',[])[:2]: print(f\"          - {driver}\")
for f in d['findings']: print(f\"    [{f['severity']}] {f['findingId']}\")"

step "5  Clean corpus -- negative control"
curl -sS "${AUTH[@]}" -F "file=@$ASSETS/clean_corpus.zip" "$BASE/api/analyze/dataset" | jq_py "
d=json.load(sys.stdin)
t=d.get('triggerAnalysis') or {}
print(f\"  {d['filename']}: risk {d['datasetRisk']}  status {d['status']}\")
print(f\"    trigger clusters: {t.get('clusterCount',0)}  (a clean corpus must produce none)\")"

step "6  Inference provenance -- seal, tamper, replay"
IH=$(python -c "import secrets;print(secrets.token_hex(32))")
MH=$(python -c "import secrets;print(secrets.token_hex(32))")
SEALED=$(curl -sS "${AUTH[@]}" -H 'content-type: application/json' -X POST "$BASE/api/inference/seal" \
  -d "{\"inputImageSha256\":\"$IH\",\"modelIdentifier\":\"traffic_recon_resnet18.pth\",\"modelSha256\":\"$MH\",\"prediction\":\"STOP_SIGN\",\"confidence\":0.9841}")

printf '%s' "$SEALED" | jq_py "
d=json.load(sys.stdin)
print(f\"  sealed {d['recordId']}: '{d['prediction']}' at {d['confidence']:.2%}\")
print(f\"    digest    : {d['recordSha256']}\")
print(f\"    signature : {d['signatureAlgorithm']} via {d['signingKeyId']}\")"

read -r RID RH SIG NONCE TS <<< "$(printf '%s' "$SEALED" | jq_py "
d=json.load(sys.stdin)
print(d['recordId'], d['recordSha256'], d['signature'], d['nonce'], d['timestampUtc'])")"

VERIFY_BODY="{\"recordId\":\"$RID\",\"inputImageSha256\":\"$IH\",\"modelIdentifier\":\"traffic_recon_resnet18.pth\",\"modelSha256\":\"$MH\",\"confidence\":0.9841,\"timestampUtc\":\"$TS\",\"nonce\":\"$NONCE\",\"recordSha256\":\"$RH\",\"signature\":\"$SIG\",\"checkReplay\":false"

echo
echo "  a) verify unmodified"
curl -sS "${AUTH[@]}" -H 'content-type: application/json' -X POST "$BASE/api/inference/verify" \
  -d "$VERIFY_BODY,\"prediction\":\"STOP_SIGN\"}" | jq_py "
d=json.load(sys.stdin)
print(f\"     -> {d['status']}  signature valid: {d['signatureValid']}\")"

echo
echo "  b) intercept in transit: STOP_SIGN -> SPEED_LIMIT"
curl -sS "${AUTH[@]}" -H 'content-type: application/json' -X POST "$BASE/api/inference/verify" \
  -d "$VERIFY_BODY,\"prediction\":\"SPEED_LIMIT\"}" | jq_py "
d=json.load(sys.stdin)
print(f\"     -> {d['status']}   altered fields: {d['alteredFields']}\")
print(f\"        recorded   {d['expectedHash'][:48]}...\")
print(f\"        recomputed {d['computedHash'][:48]}...\")"

echo
echo "  c) replay the consumed nonce"
curl -sS "${AUTH[@]}" -H 'content-type: application/json' -X POST "$BASE/api/inference/seal" \
  -d "{\"inputImageSha256\":\"$IH\",\"modelIdentifier\":\"traffic_recon_resnet18.pth\",\"modelSha256\":\"$MH\",\"prediction\":\"SPEED_LIMIT\",\"confidence\":0.9841,\"nonce\":\"$NONCE\"}" | jq_py "
d=json.load(sys.stdin)
print(f\"     -> refused [{d.get('code')}] {d.get('error','')[:100]}\")"

step "7  Governance decision"
curl -sS "${AUTH[@]}" "$BASE/api/governance/decision" | jq_py "
d=json.load(sys.stdin)
print(f\"  DECISION: {d['decision']}    composite risk {d['overallRisk']}/100    trust {d['trustScore']}/100\")
print(f\"  bands: ACCEPT < {d['thresholds']['acceptBelow']} | REVIEW {d['thresholds']['acceptBelow']}-{d['thresholds']['quarantineAtOrAbove']-1} | QUARANTINE >= {d['thresholds']['quarantineAtOrAbove']}\")
print('  triggered rules:')
for r in d['triggeredRules']: print(f'    - {r}')
print(f\"  rationale: {d['rationale']}\")"

step "8  Audit ledger"
curl -sS "${AUTH[@]}" "$BASE/api/audit/verify-chain" | jq_py "
d=json.load(sys.stdin)
print(f\"  chain valid : {d['valid']}\")
print(f\"  blocks      : {d['chainLength']}  ({d['signedBlocks']} Ed25519-signed, {d['signatureFailures']} signature failures)\")
print(f\"  head        : {d['headHash']}\")
print(f\"  {d['details']}\")"

step "9  Signed assurance report"
curl -sS "${AUTH[@]}" "$BASE/api/governance/report" | jq_py "
d=json.load(sys.stdin)
print(f\"  {d['reportId']}  [{d['classification']}]\")
print(f\"  decision {d['decision']}  risk {d['risk']['overallRisk']}  trust {d['risk']['trustScore']}\")
print(f\"  findings: {d['findings']['critical']} critical, {d['findings']['high']} high, {d['findings']['medium']} medium\")
print(f\"  seal    : {d['seal']['algorithm']} over {d['seal']['canonicalization']}\")
print(f\"            sha-256 {d['seal']['sha256'][:48]}...\")"

rule
printf '\033[1;32m  Walkthrough complete. Plain-text report: %s/api/governance/report.txt\033[0m\n' "$BASE"
rule
