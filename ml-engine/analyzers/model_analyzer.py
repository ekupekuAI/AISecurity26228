"""Model integrity engine.

Runs the model workflow from the problem statement and, critically, reports *what access
it actually obtained*. The distinction between "we ran the model and found nothing" and
"we could not run the model" is the difference between evidence of absence and absence of
evidence, and an assurance tool that blurs it is worse than useless in a defence context.

Pipeline: digest -> container identification -> static opcode audit -> structural parse
-> weight statistics -> [white-box only] behavioural battery -> [white-box only] trigger
inversion -> fused risk.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from analyzers import risk_engine
from analyzers.coverage import model_coverage
from core.config import SETTINGS
from core.models import AnalysisMode, make_finding, new_id, sort_findings, utc_now
from modelscan import battery as battery_module
from modelscan import neural_cleanse, onnx_inspect, onnx_runtime, torch_inspect, weight_stats
from security.pickle_audit import audit_checkpoint

SUPPORTED_EXTENSIONS = {".pt", ".pth", ".onnx", ".ts", ".torchscript", ".safetensors", ".bin"}

#: Largest spatial resolution used for behavioural testing. Inversion cost scales with
#: the square of this, and a 224px scan of a 10-class model does not finish inside an
#: operational review window on CPU.
ANALYSIS_RESOLUTION_CAP = 96


def _extension(filename: str) -> str:
    return "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


class ModelAnalyzer:
    @classmethod
    def analyze(cls, filename: str, data: bytes) -> dict[str, Any]:
        started = time.perf_counter()
        sha256 = hashlib.sha256(data).hexdigest()
        extension = _extension(filename)
        findings: list[dict[str, Any]] = []

        base = {
            "id": new_id("MOD"),
            "filename": filename,
            "sha256": sha256,
            "fileSizeBytes": len(data),
            "engine": "python-full",
            "timestamp": utc_now(),
        }

        if extension not in SUPPORTED_EXTENSIONS:
            findings.append(
                make_finding(
                    finding_id="MOD-UNSUPPORTED-FORMAT",
                    category="MODEL",
                    severity="LOW",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=(
                        f"Extension '{extension}' is not a recognised checkpoint format. Supported: "
                        f"{', '.join(sorted(SUPPORTED_EXTENSIONS))}."
                    ),
                    evidence={"extension": extension, "sizeBytes": len(data)},
                    recommendation="Re-export the model as ONNX or TorchScript. ONNX is preferred: it carries no executable pickle.",
                    detector="analyzers.model_analyzer",
                    threshold="extension allowlist",
                )
            )
            return cls._result(
                base,
                findings=findings,
                mode=AnalysisMode.REFUSED,
                status="NOT SUPPORTED",
                framework="Unknown",
                architecture="Unsupported format",
                risk=20.0,
                risk_breakdown={"unsupported": 20.0},
                limitations=(
                    "No analysis was performed. This is a coverage gap, not a clean result: the "
                    "file may still be malicious."
                ),
                started=started,
            )

        if extension == ".onnx":
            return cls._analyse_onnx(base, filename, data, findings, started)
        if extension == ".safetensors":
            return cls._analyse_safetensors(base, filename, data, findings, started)
        return cls._analyse_torch(base, filename, data, findings, started)

    # -- ONNX ------------------------------------------------------------------

    @classmethod
    def _analyse_onnx(
        cls, base: dict[str, Any], filename: str, data: bytes, findings: list[dict[str, Any]], started: float
    ) -> dict[str, Any]:
        inspection = onnx_inspect.inspect(data)

        if not inspection.parsed:
            findings.append(
                make_finding(
                    finding_id="MOD-ONNX-UNPARSEABLE",
                    category="MODEL",
                    severity="HIGH",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=(
                        "The file carries an .onnx extension but does not parse as an ONNX "
                        "ModelProto. A checkpoint whose declared format is a lie must be treated "
                        "as hostile until proven otherwise."
                    ),
                    evidence=inspection.to_dict(),
                    recommendation="Reject the submission and require a re-export verified with onnx.checker.",
                    detector="modelscan.onnx_inspect",
                    threshold="protobuf ModelProto conformance",
                )
            )
            return cls._result(
                base,
                findings=findings,
                mode=AnalysisMode.BLACK_BOX,
                status="ANALYSIS FAILED",
                framework="ONNX (claimed)",
                architecture="Unparseable",
                risk=75.0,
                risk_breakdown={"unparseable": 75.0},
                limitations="Graph could not be read; no structural or behavioural claim is possible.",
                onnx=inspection.to_dict(),
                started=started,
            )

        if inspection.suspicious_operators:
            findings.append(
                make_finding(
                    finding_id="MOD-ONNX-SUSPICIOUS-OPERATORS",
                    category="MODEL",
                    severity="HIGH",
                    confidence=0.85,
                    affected_asset=filename,
                    explanation=(
                        f"The graph contains {len(inspection.suspicious_operators)} operators that do "
                        "not belong in a vision inference graph. Control-flow and custom-domain "
                        "operators can gate behaviour on an input pattern, which is how a backdoor "
                        "is expressed structurally rather than in the weights."
                    ),
                    evidence={
                        "operators": inspection.suspicious_operators[:20],
                        "customDomains": inspection.custom_domains,
                        "operatorHistogram": inspection.operator_histogram,
                    },
                    recommendation="Require a re-export using only standard ai.onnx operators, and diff the graph against the vendor's published topology.",
                    detector="modelscan.onnx_inspect",
                    threshold="operator allowlist + custom domain detection",
                )
            )

        if inspection.orphan_nodes:
            findings.append(
                make_finding(
                    finding_id="MOD-ONNX-ORPHAN-NODES",
                    category="MODEL",
                    severity="MEDIUM",
                    confidence=0.8,
                    affected_asset=filename,
                    explanation=(
                        f"{len(inspection.orphan_nodes)} nodes produce outputs that nothing consumes "
                        "and that are not graph outputs. Dead subgraphs are usually export debris, "
                        "but they are also where an unused-until-triggered path would sit."
                    ),
                    evidence={"orphanNodes": inspection.orphan_nodes[:20]},
                    recommendation="Ask the vendor to explain or prune the dead subgraph before acceptance.",
                    detector="modelscan.onnx_inspect",
                    threshold="node outputs not consumed and not graph outputs",
                )
            )

        weights = weight_stats.analyse_weights(inspection.tensors)
        findings.extend(cls._weight_findings(filename, weights))

        # --- behavioural (forward-only via onnxruntime) -------------------------
        # ONNX carries no gradients, so Neural Cleanse trigger inversion cannot run here.
        # But the behavioural battery needs only forward passes, and onnxruntime provides
        # them. Running it makes ONNX a genuinely executed check rather than a structural
        # one, while the trigger-inversion limitation is disclosed rather than hidden.
        battery_report = battery_module.BatteryReport()
        backdoor_confidence = 0.0
        executed = False
        runner = onnx_runtime.load_runner(data)

        if runner.available and runner.runnable:
            channels = runner.channels or 3
            classes = int(runner.output_classes)
            size = cls._select_onnx_resolution(runner, channels, classes)
            if size > 0:
                battery_report = battery_module.run_battery_predict(runner.predict, classes, channels, size)
                executed = battery_report.ran
                if battery_report.ran and not battery_report.degenerate:
                    backdoor_confidence = battery_report.backdoor_confidence
                    findings.extend(cls._battery_findings(filename, battery_report))
            else:
                runner.notes.append(
                    "The graph declares a fixed non-square input, which the square trigger battery "
                    "does not drive; behavioural testing was skipped."
                )

        # Explicit capability/limitation disclosure for the behavioural dimension.
        if executed and not battery_report.degenerate:
            findings.append(
                make_finding(
                    finding_id="MOD-ONNX-TRIGGER-INVERSION-UNAVAILABLE",
                    category="MODEL",
                    severity="INFO",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=(
                        "The behavioural trigger battery ran against this ONNX graph via forward "
                        "inference. Neural Cleanse optimisation-based trigger inversion did NOT run: "
                        "it requires gradients, which the ONNX runtime path does not expose. A "
                        "concentrated flip under the battery is strong positive evidence; the absence "
                        "of one only rules out the trigger families the battery tests, not every "
                        "possible backdoor. Export to TorchScript for gradient-based certification."
                    ),
                    evidence={"onnxRuntime": runner.to_dict(), "batteryRan": True},
                    recommendation="For full white-box certification, supply the model as TorchScript so trigger inversion can run.",
                    detector="modelscan.onnx_runtime.load_runner",
                    threshold="onnxruntime forward pass available; gradients not available",
                )
            )
        else:
            reason = (
                "; ".join((runner.errors + runner.notes)[:2])
                or "the ONNX graph could not be driven as an image classifier"
            )
            findings.append(
                make_finding(
                    finding_id="MOD-ONNX-BEHAVIOURAL-UNAVAILABLE",
                    category="MODEL",
                    severity="LOW",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=(
                        "Behavioural testing (trigger battery) did not run on this ONNX model: "
                        f"{reason}. Structural and weight-level analysis are complete, but no "
                        "behavioural conclusion can be drawn, and absence of a backdoor finding here "
                        "is a coverage gap rather than evidence of absence."
                    ),
                    evidence={"onnxRuntime": runner.to_dict()},
                    recommendation=(
                        "Install onnxruntime on the inspection node to enable ONNX behavioural testing, "
                        "or supply the model as TorchScript for full white-box certification."
                    ),
                    detector="modelscan.onnx_runtime.load_runner",
                    threshold="onnxruntime session runnable as an image classifier",
                )
            )

        finding_risk = risk_engine.findings_risk(findings)
        risk, breakdown = risk_engine.model_risk(
            finding_risk=finding_risk,
            serialization_verdict="CLEAN",
            backdoor_confidence=backdoor_confidence,
            weight_anomaly_score=weights.anomaly_score,
            structural_anomaly_score=inspection.structural_anomaly_score,
        )

        limitations = (
            "ONNX carries no executable pickle, so the deserialisation risk class is absent by "
            "construction. Structural analysis is complete. "
            + (
                "The behavioural trigger battery ran via onnxruntime forward inference. "
                if executed and not battery_report.degenerate
                else "The behavioural trigger battery did not run (see the coverage findings). "
            )
            + "Neural Cleanse trigger inversion is not available for ONNX because the runtime does "
            "not expose gradients for mask optimisation; export to TorchScript if gradient-based "
            "trigger inversion is required."
        )

        return cls._result(
            base,
            findings=findings,
            mode=AnalysisMode.GREY_BOX,
            status=None,
            framework=f"ONNX (IR v{inspection.ir_version}, parser: {inspection.parser})",
            architecture=f"ONNX computation graph, {inspection.node_count} nodes",
            parameter_count=inspection.parameter_count or weights.total_parameters,
            risk=risk,
            risk_breakdown=breakdown,
            backdoor_confidence=backdoor_confidence,
            limitations=limitations,
            onnx=inspection.to_dict(),
            weights=weights.to_dict(),
            battery=battery_report.to_dict(),
            onnx_runtime=runner.to_dict(),
            coverage=[
                entry.to_dict()
                for entry in model_coverage(
                    executed=executed and not battery_report.degenerate,
                    architecture_recovered=True,
                    neural_cleanse_ran=False,
                    serialization_verdict="CLEAN",
                    format_name="ONNX",
                )
            ],
            started=started,
        )

    # -- safetensors -----------------------------------------------------------

    @classmethod
    def _analyse_safetensors(
        cls, base: dict[str, Any], filename: str, data: bytes, findings: list[dict[str, Any]], started: float
    ) -> dict[str, Any]:
        import json
        import struct

        header_info: dict[str, Any] = {}
        parameter_count = 0
        try:
            (header_length,) = struct.unpack("<Q", data[:8])
            if header_length > 100_000_000 or 8 + header_length > len(data):
                raise ValueError("header length declares more bytes than the file contains")
            header = json.loads(data[8 : 8 + header_length].decode("utf-8"))
            for name, spec in header.items():
                if name == "__metadata__" or not isinstance(spec, dict):
                    continue
                shape = spec.get("shape") or []
                count = 1
                for dim in shape:
                    count *= int(dim)
                parameter_count += count
            header_info = {
                "tensorCount": len([k for k in header if k != "__metadata__"]),
                "metadata": header.get("__metadata__", {}),
                "parameterCount": parameter_count,
            }
        except Exception as exc:  # noqa: BLE001
            findings.append(
                make_finding(
                    finding_id="MOD-SAFETENSORS-MALFORMED",
                    category="MODEL",
                    severity="HIGH",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=f"The safetensors header could not be parsed: {type(exc).__name__}: {exc}",
                    evidence={"sizeBytes": len(data)},
                    recommendation="Re-export the checkpoint; the file is truncated or is not safetensors.",
                    detector="analyzers.model_analyzer",
                    threshold="safetensors header conformance",
                )
            )

        finding_risk = risk_engine.findings_risk(findings)
        risk, breakdown = risk_engine.model_risk(
            finding_risk=finding_risk,
            serialization_verdict="CLEAN",
            backdoor_confidence=0.0,
            weight_anomaly_score=0.0,
            structural_anomaly_score=0.0,
        )

        return cls._result(
            base,
            findings=findings,
            mode=AnalysisMode.GREY_BOX,
            status=None,
            framework="safetensors",
            architecture=f"Tensor container, {header_info.get('tensorCount', 0)} tensors",
            parameter_count=parameter_count,
            risk=risk,
            risk_breakdown=breakdown,
            limitations=(
                "safetensors is a pure data container with no executable code path, which removes "
                "the deserialisation risk class entirely. It also carries no topology, so no "
                "structural or behavioural analysis is possible from the file alone."
            ),
            safetensors=header_info,
            started=started,
        )

    # -- PyTorch ---------------------------------------------------------------

    @classmethod
    def _analyse_torch(
        cls, base: dict[str, Any], filename: str, data: bytes, findings: list[dict[str, Any]], started: float
    ) -> dict[str, Any]:
        inspection = torch_inspect.inspect(filename, data)
        audit = inspection.audit or audit_checkpoint(data, filename)

        # --- serialisation security --------------------------------------------
        if audit.verdict == "MALICIOUS":
            if audit.critical:
                explanation = (
                    f"The checkpoint's pickle stream names {len(audit.critical)} execution "
                    "primitive(s). Calling torch.load on this file would run attacker-controlled "
                    "code on the node before any tensor is read."
                )
                finding_id = "SEC-MALICIOUS-PICKLE-OPCODE"
            else:
                explanation = (
                    "One or more pickle streams failed to disassemble cleanly. Opcodes preceding the "
                    "failure would already have executed under torch.load. This is the published "
                    "nullifAI evasion pattern: a payload placed at the head of a deliberately broken "
                    "stream, which scanners that treat a parse error as 'nothing found' will pass."
                )
                finding_id = "SEC-BROKEN-PICKLE-STREAM"

            findings.append(
                make_finding(
                    finding_id=finding_id,
                    category="SUPPLY_CHAIN",
                    severity="CRITICAL",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=explanation,
                    evidence=audit.to_dict(),
                    recommendation=(
                        "QUARANTINE the file immediately. Do not call torch.load on any node. "
                        "Preserve it for forensics and treat the supplying vendor's entire catalogue "
                        "as compromised until audited."
                    ),
                    detector="security.pickle_audit.audit_checkpoint",
                    threshold="any critical global, or any stream that fails full disassembly",
                    references=["ReversingLabs nullifAI (2025)", "MITRE ATLAS AML.T0010", "CWE-502"],
                )
            )

            risk, breakdown = risk_engine.model_risk(
                finding_risk=100.0,
                serialization_verdict="MALICIOUS",
                backdoor_confidence=0.0,
                weight_anomaly_score=0.0,
                structural_anomaly_score=0.0,
            )
            return cls._result(
                base,
                findings=findings,
                mode=AnalysisMode.REFUSED,
                status="DETECTED",
                framework="PyTorch (compromised)",
                architecture="Untrusted checkpoint - not deserialised",
                risk=risk,
                risk_breakdown=breakdown,
                limitations=(
                    "The checkpoint was never deserialised, so no structural or behavioural analysis "
                    "was performed. That is the correct outcome: the file is disqualified on "
                    "serialisation grounds alone."
                ),
                pickle_audit=audit.to_dict(),
                coverage=[
                    entry.to_dict()
                    for entry in model_coverage(
                        executed=False,
                        architecture_recovered=False,
                        neural_cleanse_ran=False,
                        serialization_verdict="MALICIOUS",
                        format_name=audit.container,
                    )
                ],
                started=started,
            )

        if audit.verdict == "SUSPICIOUS":
            findings.append(
                make_finding(
                    finding_id="SEC-PICKLE-ANOMALY",
                    category="SUPPLY_CHAIN",
                    severity="HIGH",
                    confidence=0.8,
                    affected_asset=filename,
                    explanation=(
                        f"The opcode audit found {len(audit.disallowed)} symbol(s) outside the set a "
                        f"legitimate checkpoint needs, in a '{audit.container}' container. "
                        + ("; ".join(audit.notes[:2]) if audit.notes else "")
                    ),
                    evidence=audit.to_dict(),
                    recommendation="Require the vendor to resupply as ONNX or safetensors before acceptance.",
                    detector="security.pickle_audit.audit_checkpoint",
                    threshold="symbol allowlist + container conformance",
                    references=["CWE-502"],
                )
            )

        if audit.container == "raw-pickle":
            findings.append(
                make_finding(
                    finding_id="MOD-LEGACY-PICKLE-FORMAT",
                    category="MODEL",
                    severity="MEDIUM",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=(
                        "The checkpoint uses the legacy uncompressed pickle serialisation. It passed "
                        "the opcode audit, but the format itself keeps arbitrary code execution one "
                        "misconfiguration away for every downstream consumer."
                    ),
                    evidence={"container": audit.container, "protocolVersions": sorted(set(audit.protocol_versions))},
                    recommendation="Re-save with torch.save(..., _use_new_zipfile_serialization=True), or preferably export to ONNX or safetensors.",
                    detector="security.pickle_audit.identify_container",
                    threshold="container == raw-pickle",
                )
            )

        if not inspection.loadable:
            for error in inspection.errors:
                findings.append(
                    make_finding(
                        finding_id="MOD-LOAD-FAILED",
                        category="MODEL",
                        severity="MEDIUM",
                        confidence=1.0,
                        affected_asset=filename,
                        explanation=f"The checkpoint passed the opcode audit but could not be parsed: {error}",
                        evidence={"container": audit.container, "notes": inspection.notes},
                        recommendation="Verify the checkpoint is complete and was produced by a supported PyTorch version.",
                        detector="modelscan.torch_inspect",
                        threshold="torch.load(weights_only=True) success",
                    )
                )

            finding_risk = risk_engine.findings_risk(findings)
            risk, breakdown = risk_engine.model_risk(
                finding_risk=finding_risk,
                serialization_verdict=audit.verdict,
                backdoor_confidence=0.0,
                weight_anomaly_score=0.0,
                structural_anomaly_score=0.3,
            )
            return cls._result(
                base,
                findings=findings,
                mode=AnalysisMode.BLACK_BOX,
                status=None,
                framework="PyTorch",
                architecture="Not recoverable",
                risk=risk,
                risk_breakdown=breakdown,
                limitations=(
                    "Only the container and its opcode stream were inspected. No parameters were "
                    "recovered, so neither weight statistics nor behavioural testing could run. "
                    "Absence of a backdoor finding here is not evidence of absence."
                ),
                pickle_audit=audit.to_dict(),
                torch=inspection.to_dict(),
                coverage=[
                    entry.to_dict()
                    for entry in model_coverage(
                        executed=False,
                        architecture_recovered=False,
                        neural_cleanse_ran=False,
                        serialization_verdict=audit.verdict,
                        format_name=audit.container,
                    )
                ],
                started=started,
            )

        # --- weights ------------------------------------------------------------
        weights = weight_stats.analyse_weights(inspection.tensors)
        findings.extend(cls._weight_findings(filename, weights))

        # --- behavioural --------------------------------------------------------
        battery_report = battery_module.BatteryReport()
        cleanse_report = neural_cleanse.NeuralCleanseReport()
        backdoor_confidence = 0.0

        resolution_note = ""
        resolution_probes: list[dict[str, Any]] = []
        # Bind size before the guard: a TorchScript checkpoint can be executable yet have no
        # inferable class head (output_classes is None for detection heads / feature extractors),
        # in which case this block is skipped and the return below still reads `size`. Leaving it
        # unbound raised UnboundLocalError and 500'd the whole /analyze/model request.
        size = 0
        if inspection.executable and inspection.module is not None and inspection.output_classes:
            channels = inspection.input_channels or 3
            size, declared_size, resolution_note, resolution_probes = cls._probe_input_size(inspection)
            if resolution_note:
                inspection.notes.append(resolution_note)

            battery_report = battery_module.run_battery(
                inspection.module, int(inspection.output_classes), channels, size
            )
            cleanse_report = neural_cleanse.run(
                inspection.module, int(inspection.output_classes), channels, size
            )

            strong = [r for r in battery_report.results if r.verdict == "STRONG_BACKDOOR_INDICATION"]

            # The behavioural battery leads; Neural Cleanse only corroborates. NC on synthetic
            # imagery is not a standalone detector: on an air-gapped node with no operational
            # data it false-positives at a rate that, measured on this very evaluation corpus,
            # made a clean model's most-invertible class look *more* anomalous (anomaly index
            # 3.5, L1 30% of median) than a 100%-ASR backdoor's real trigger class (index 1.0,
            # L1 36%), because a backdoored model has several easily-flipped classes that
            # inflate the MAD and suppress the true target's index. The battery does not share
            # that failure mode. So NC's confidence enters the headline, and NC earns a
            # confirmed-backdoor finding, only when it agrees with the battery on the same
            # class; on its own it is a disclosed lead, never a detection.
            battery_targets = {r.target_class for r in strong if r.target_class is not None}

            strongest = None
            corroborated = False
            if cleanse_report.flagged_classes:
                flagged = [i for i in cleanse_report.inversions if i.flagged]
                strongest = min(flagged, key=lambda i: i.l1_norm)
                corroborated = strongest.class_index in battery_targets

            backdoor_confidence = risk_engine.fuse_confidence(
                [
                    battery_report.backdoor_confidence,
                    cleanse_report.backdoor_confidence if corroborated else 0.0,
                ]
            )

            if strongest is not None:
                # Which condition actually fired? The detector flags on a decisive L1
                # ratio OR on the anomaly index backed by a looser ratio, and the
                # explanation must say which. Claiming the index "passed" when it read
                # 1.98 against a 2.0 threshold is the kind of detail an assessor checks
                # first, and getting it wrong discredits everything beside it.
                index_passed = (
                    strongest.anomaly_index > SETTINGS.thresholds.neural_cleanse_anomaly_index
                )
                ratio_decisive = (
                    strongest.l1_ratio <= SETTINGS.thresholds.neural_cleanse_l1_ratio_decisive
                )
                if index_passed and ratio_decisive:
                    basis = (
                        f"sits {strongest.anomaly_index:.2f} MADs from the median, past the "
                        f"{SETTINGS.thresholds.neural_cleanse_anomaly_index:.1f} anomaly-index "
                        f"threshold, and is independently below the "
                        f"{SETTINGS.thresholds.neural_cleanse_l1_ratio_decisive:.0%} decisive "
                        "ratio band"
                    )
                elif ratio_decisive:
                    basis = (
                        f"is below the {SETTINGS.thresholds.neural_cleanse_l1_ratio_decisive:.0%} "
                        "decisive ratio band. The MAD anomaly index reads "
                        f"{strongest.anomaly_index:.2f} against a "
                        f"{SETTINGS.thresholds.neural_cleanse_anomaly_index:.1f} threshold and did "
                        "not fire on its own; it is normalised over as few as ten values and is "
                        "correspondingly noisy, so the ratio is the statistic relied on here"
                    )
                else:
                    basis = (
                        f"sits {strongest.anomaly_index:.2f} MADs from the median, past the "
                        f"{SETTINGS.thresholds.neural_cleanse_anomaly_index:.1f} anomaly-index "
                        f"threshold, with the ratio inside the "
                        f"{SETTINGS.thresholds.neural_cleanse_l1_ratio_max:.0%} corroborating band"
                    )

                findings.append(
                    make_finding(
                        # Corroboration decides the id and the weight. A battery-corroborated
                        # inversion is a confirmed backdoor (MOD-NEURAL-CLEANSE-TRIGGER, which
                        # governance treats as a mandatory quarantine). An uncorroborated one is
                        # a disclosed lead (MOD-NEURAL-CLEANSE-LEAD, LOW): recorded for an analyst
                        # but not permitted to condemn the asset on its own, because NC's
                        # standalone false-positive rate on synthetic data is too high to carry a
                        # detection alone.
                        finding_id="MOD-NEURAL-CLEANSE-TRIGGER" if corroborated else "MOD-NEURAL-CLEANSE-LEAD",
                        category="MODEL",
                        severity="CRITICAL" if corroborated else "LOW",
                        confidence=cleanse_report.backdoor_confidence * (1.0 if corroborated else 0.7),
                        affected_asset=f"{filename} (target class {strongest.class_index})",
                        explanation=(
                            f"Optimisation-based trigger inversion recovered a universal perturbation "
                            f"that forces class {strongest.class_index} while covering only "
                            f"{strongest.l1_fraction:.2%} of the input. Its L1 mask norm is "
                            f"{strongest.l1_ratio:.0%} of the across-class median, which "
                            f"{basis}. A class reachable by a perturbation this much smaller than "
                            "every other class is the defining signature of an implanted shortcut. "
                            + (
                                f"The behavioural battery independently drove inputs to the same class "
                                f"{strongest.class_index}, so two methods with different assumptions agree."
                                if corroborated
                                else "The behavioural battery did not corroborate this class, so this is "
                                "a single-detector result. Trigger inversion has a non-trivial false-positive "
                                "rate on clean models; treat this as a lead requiring analyst adjudication "
                                "rather than a confirmed backdoor."
                            )
                        ),
                        evidence={**cleanse_report.to_dict(), "corroboratedByBattery": corroborated},
                        recommendation=(
                            "QUARANTINE the checkpoint. Do not deploy. Retrain from a trusted base or "
                            "obtain a re-signed checkpoint from the vendor with provenance evidence."
                            if corroborated
                            else "Withhold deployment authorisation pending analyst review. Re-run the "
                            "assessment with a larger inversion budget and, if available, evaluate the "
                            "checkpoint against held-out operational data before deciding."
                        ),
                        detector="modelscan.neural_cleanse.run",
                        threshold=(
                            "attack success >= 0.85 AND ("
                            f"L1 <= {SETTINGS.thresholds.neural_cleanse_l1_ratio_decisive:.0%} of median "
                            f"OR (MAD anomaly index > {SETTINGS.thresholds.neural_cleanse_anomaly_index:.1f} "
                            f"AND L1 <= {SETTINGS.thresholds.neural_cleanse_l1_ratio_max:.0%} of median))"
                            f"; fired on {'both conditions' if index_passed and ratio_decisive else ('the decisive ratio band' if ratio_decisive else 'the anomaly index')}"
                            + ("; corroborated by behavioural battery" if corroborated else "; not corroborated")
                        ),
                        references=["Wang et al., Neural Cleanse (IEEE S&P 2019)"],
                    )
                )

            if strong:
                worst = max(strong, key=lambda r: r.flip_rate * r.concentration)
                findings.append(
                    make_finding(
                        finding_id="MOD-BEHAVIOURAL-BACKDOOR-RESPONSE",
                        category="MODEL",
                        severity="CRITICAL",
                        confidence=battery_report.backdoor_confidence,
                        affected_asset=f"{filename} (target class {worst.target_class})",
                        explanation=(
                            f"Under the '{worst.name}' trigger battery, {worst.flip_rate:.1%} of "
                            f"reference inputs changed prediction, and {worst.concentration:.1%} of "
                            f"those flips landed on the single class {worst.target_class}. Ordinary "
                            "perturbation sensitivity scatters predictions across classes; "
                            "concentration this high is a directed response."
                        ),
                        evidence=battery_report.to_dict(),
                        recommendation="QUARANTINE the checkpoint and escalate to the model validation authority.",
                        detector="modelscan.battery.run_battery",
                        threshold="flip rate >= 50% with >= 85% concentration on one class",
                        references=["Gu et al., BadNets (2017)"],
                    )
                )
            # White-box access is not the same as complete coverage. If inversion was cut
            # short, an unscanned class could still host a backdoor and the assessment must
            # say so rather than leaving a silent gap behind a clean verdict.
            if not cleanse_report.ran or cleanse_report.classes_scanned < int(inspection.output_classes):
                findings.append(
                    make_finding(
                        finding_id="MOD-TRIGGER-SCAN-INCOMPLETE",
                        category="MODEL",
                        severity="MEDIUM",
                        confidence=1.0,
                        affected_asset=filename,
                        explanation=(
                            f"Trigger inversion covered {cleanse_report.classes_scanned} of "
                            f"{inspection.output_classes} output classes"
                            + (
                                f": {cleanse_report.errors[0]}"
                                if cleanse_report.errors
                                else " and did not reach a scoreable comparison."
                            )
                            + " An unscanned class could host a backdoor that this assessment did "
                            "not look for."
                        ),
                        evidence={
                            "classesScanned": cleanse_report.classes_scanned,
                            "classesTotal": cleanse_report.classes_total,
                            "errors": cleanse_report.errors,
                            "durationSeconds": round(cleanse_report.duration_seconds, 1),
                        },
                        recommendation=(
                            "Re-run the model assessment with an increased inversion budget "
                            "(AIA_NEURAL_CLEANSE_TIMEOUT) before granting operational authorisation."
                        ),
                        detector="modelscan.neural_cleanse.run",
                        threshold="classes scanned == output classes",
                    )
                )

            if any(r.verdict == "SUSPICIOUS" for r in battery_report.results) and not strong:
                suspicious = [r for r in battery_report.results if r.verdict == "SUSPICIOUS"]
                findings.append(
                    make_finding(
                        finding_id="MOD-TRIGGER-SENSITIVITY",
                        category="MODEL",
                        severity="MEDIUM",
                        confidence=0.55,
                        affected_asset=filename,
                        explanation=(
                            f"{len(suspicious)} trigger batteries produced a moderately concentrated "
                            "label shift. This is below the threshold for a backdoor call but above "
                            "what a robust model should show, and warrants adversarial evaluation "
                            "against operational data."
                        ),
                        evidence=battery_report.to_dict(),
                        recommendation="Run an adversarial robustness evaluation on representative mission data before release.",
                        detector="modelscan.battery.run_battery",
                        threshold="flip rate >= 30% with >= 70% concentration",
                    )
                )
        else:
            reason = (
                "the architecture could not be reconstructed from the state dict"
                if inspection.loadable
                else "the checkpoint could not be loaded"
            )
            findings.append(
                make_finding(
                    finding_id="MOD-WHITEBOX-UNAVAILABLE",
                    category="MODEL",
                    severity="LOW",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=(
                        f"Behavioural testing and trigger inversion did not run because {reason}. "
                        "Parameter-level analysis is complete, but no behavioural conclusion can be "
                        "drawn and absence of a backdoor finding must not be read as absence of a "
                        "backdoor."
                    ),
                    evidence={
                        "loadable": inspection.loadable,
                        "executable": inspection.executable,
                        "outputClasses": inspection.output_classes,
                        "notes": inspection.notes,
                    },
                    recommendation="Request the checkpoint as TorchScript or ONNX to enable full white-box certification.",
                    detector="modelscan.torch_inspect._try_reconstruct",
                    threshold="strict state-dict load into a known architecture",
                )
            )

        finding_risk = risk_engine.findings_risk(findings)
        risk, breakdown = risk_engine.model_risk(
            finding_risk=finding_risk,
            serialization_verdict=audit.verdict,
            backdoor_confidence=backdoor_confidence,
            weight_anomaly_score=weights.anomaly_score,
            structural_anomaly_score=0.0 if inspection.executable else 0.15,
        )

        mode = AnalysisMode.WHITE_BOX if inspection.executable else (
            AnalysisMode.GREY_BOX if inspection.loadable else AnalysisMode.BLACK_BOX
        )

        return cls._result(
            base,
            findings=findings,
            mode=mode,
            status=None,
            framework=f"PyTorch ({audit.container} container)",
            architecture=inspection.architecture,
            parameter_count=inspection.parameter_count,
            risk=risk,
            risk_breakdown=breakdown,
            backdoor_confidence=backdoor_confidence,
            limitations=cls._compose_limitations(mode, cleanse_report, battery_report, resolution_note),
            pickle_audit=audit.to_dict(),
            torch=inspection.to_dict(),
            weights=weights.to_dict(),
            battery=battery_report.to_dict(),
            neural_cleanse=cleanse_report.to_dict(),
            resolution={"chosen": size or None, "probes": resolution_probes},
            coverage=[
                entry.to_dict()
                for entry in model_coverage(
                    executed=inspection.executable,
                    architecture_recovered=inspection.architecture_confidence >= 0.8,
                    neural_cleanse_ran=cleanse_report.ran,
                    serialization_verdict=audit.verdict,
                    format_name=audit.container,
                )
            ],
            started=started,
        )

    # -- shared helpers --------------------------------------------------------

    @staticmethod
    def _probe_input_size(inspection: torch_inspect.TorchInspection) -> tuple[int, int, str, list[dict[str, Any]]]:
        """Choose the analysis resolution by measuring the model, not by guessing.

        Returns ``(chosen, declared, note, probe_table)``.

        Reading the resolution off the stem kernel is wrong often enough to matter. A 7x7
        stem nominally implies 224x224, but a checkpoint fine-tuned on 32x32 imagery
        routinely keeps that stem. Evaluating such a model at 224 puts every input far
        outside its training distribution, and the consequences are not subtle: the model
        saturates onto one or two classes at ~1.0 confidence, the behavioural baseline
        collapses, and both the trigger battery and Neural Cleanse then measure
        off-distribution artefacts rather than the backdoor. Measured on a real pair of
        CIFAR-fine-tuned ResNet-18s, that produced a CRITICAL verdict on the clean model
        and a clean verdict on a model with a 100% attack success rate -- the detector
        inverted.

        So each accepted resolution is scored by how *discriminating* the model is there:
        prediction entropy over the clean reference battery, lightly penalised for
        saturated confidence. A model probed at its training resolution answers with
        several classes at moderate confidence; probed off-distribution it collapses. The
        highest-scoring resolution wins, with ties broken toward the cheaper one.
        """
        try:
            import torch
        except Exception:  # noqa: BLE001
            return 64, 64, "", []

        stem = inspection.tensors.get("conv1.weight")
        declared = 224
        if stem is not None and getattr(stem, "ndim", 0) == 4:
            declared = 32 if stem.shape[-1] == 3 else 224

        channels = inspection.input_channels or 3
        module = inspection.module
        classes = int(inspection.output_classes or 0)
        if module is None or classes < 2:
            return declared, declared, "", []

        candidates = [size for size in (32, 64, 96, 128, 224) if size <= ANALYSIS_RESOLUTION_CAP or size == declared]
        if declared not in candidates:
            candidates.append(declared)

        probes: list[dict[str, Any]] = []
        for size in sorted(set(candidates)):
            try:
                with torch.inference_mode():
                    output = module(torch.zeros(1, channels, size, size))
                if isinstance(output, (tuple, list)):
                    output = output[0]
                if output.ndim < 2 or int(output.shape[-1]) != classes:
                    continue
            except Exception:  # noqa: BLE001 - this resolution is simply not usable
                continue

            metrics = battery_module.baseline_diversity(module, classes, channels, size, samples=48)
            probes.append({"size": size, **{k: round(v, 4) for k, v in metrics.items()}})

        if not probes:
            return declared, declared, (
                "No probed input resolution produced a usable forward pass, so the size inferred "
                "from the stem kernel was used. Behavioural results should be treated as unreliable."
            ), []

        # Prefer the *smallest* resolution that is within a margin of the most discriminating
        # one, rather than the strict argmax. Two reasons, both about not missing a backdoor:
        #  * A small entropy gain at a larger frame does not justify moving off the training
        #    resolution. On a real backdoored CIFAR ResNet, size 64 scored 1.56 bits against
        #    32's 1.31 -- a 0.25-bit edge -- and evaluating the battery at 64 shrank the 4x4
        #    trigger relative to the frame until it no longer fired, hiding a 100%-ASR backdoor.
        #  * The trigger battery stamps a fixed-size patch, so a smaller frame makes the patch
        #    proportionally larger and more likely to fire. Biasing toward the smaller frame is
        #    therefore the safer error for detection, never the more dangerous one.
        best_score = max(p["score"] for p in probes)
        margin = 0.5
        qualifying = [p for p in probes if p["score"] >= best_score - margin]
        best = min(qualifying, key=lambda p: p["size"])
        chosen = int(best["size"])

        note = ""
        if chosen != declared:
            note = (
                f"Behavioural testing and trigger inversion ran at {chosen}x{chosen}. The stem "
                f"kernel nominally implies {declared}x{declared}, but the model is measurably more "
                f"discriminating at {chosen}: {best['entropy']:.2f} bits of prediction entropy "
                f"across {int(best['distinctClasses'])} classes at {best['meanConfidence']:.2f} mean "
                "confidence. Evaluating a checkpoint outside its training resolution collapses the "
                "baseline and makes every trigger measurement meaningless, so the resolution is "
                "selected by measurement rather than by the stem."
            )
        if best["entropy"] < 1.0:
            note += (
                " Note: even the best resolution yields a near-collapsed baseline, so behavioural "
                "findings from this model carry low confidence and are reported as a coverage gap."
            )
        return chosen, declared, note, probes

    @staticmethod
    def _select_onnx_resolution(runner: onnx_runtime.OnnxRunner, channels: int, classes: int) -> int:
        """Pick the resolution to drive an ONNX battery at.

        A fixed square input is used as declared. A dynamic input is probed the same way the
        torch path probes: the most discriminating resolution (highest prediction entropy)
        wins, because a model evaluated far off its training resolution collapses its baseline
        and makes every trigger measurement meaningless. A fixed non-square input returns 0 to
        signal "cannot drive the square battery".
        """
        if runner.spatial_fixed:
            return int(runner.height) if runner.height == runner.width else 0

        probes = [
            metrics
            for size in (32, 64, 96)
            for metrics in [battery_module.diversity_from_predict(runner.predict, channels, size, samples=32)]
            if metrics["score"] > -1.0
        ]
        if not probes:
            return 64
        best = max(probes, key=lambda p: (p["score"], -p["size"]))
        return int(best["size"])

    @staticmethod
    def _battery_findings(filename: str, battery_report: battery_module.BatteryReport) -> list[dict[str, Any]]:
        """Behavioural findings from a battery report, independent of trigger inversion.

        Used on the ONNX path, where the battery runs but Neural Cleanse cannot. The finding
        ids match the torch path, so an ONNX backdoor drives the same BACKDOOR_CONFIRMED
        governance override a TorchScript one would.
        """
        findings: list[dict[str, Any]] = []
        strong = [r for r in battery_report.results if r.verdict == "STRONG_BACKDOOR_INDICATION"]
        if strong:
            worst = max(strong, key=lambda r: r.flip_rate * r.concentration)
            findings.append(
                make_finding(
                    finding_id="MOD-BEHAVIOURAL-BACKDOOR-RESPONSE",
                    category="MODEL",
                    severity="CRITICAL",
                    confidence=battery_report.backdoor_confidence,
                    affected_asset=f"{filename} (target class {worst.target_class})",
                    explanation=(
                        f"Under the '{worst.name}' trigger battery run through onnxruntime, "
                        f"{worst.flip_rate:.1%} of reference inputs changed prediction, and "
                        f"{worst.concentration:.1%} of those flips landed on the single class "
                        f"{worst.target_class}. Ordinary perturbation sensitivity scatters "
                        "predictions across classes; concentration this high is a directed response, "
                        "which is the behavioural signature of an implanted backdoor."
                    ),
                    evidence=battery_report.to_dict(),
                    recommendation="QUARANTINE the checkpoint and escalate to the model validation authority.",
                    detector="modelscan.battery.run_battery_predict",
                    threshold="flip rate >= 50% with >= 85% concentration on one class and lift >= 3x",
                    references=["Gu et al., BadNets (2017)"],
                )
            )
        elif any(r.verdict == "SUSPICIOUS" for r in battery_report.results):
            suspicious = [r for r in battery_report.results if r.verdict == "SUSPICIOUS"]
            findings.append(
                make_finding(
                    finding_id="MOD-TRIGGER-SENSITIVITY",
                    category="MODEL",
                    severity="MEDIUM",
                    confidence=0.55,
                    affected_asset=filename,
                    explanation=(
                        f"{len(suspicious)} trigger batteries produced a moderately concentrated label "
                        "shift under forward inference. This is below the threshold for a backdoor call "
                        "but above what a robust model should show, and warrants adversarial evaluation "
                        "against operational data."
                    ),
                    evidence=battery_report.to_dict(),
                    recommendation="Run an adversarial robustness evaluation on representative mission data before release.",
                    detector="modelscan.battery.run_battery_predict",
                    threshold="flip rate >= 30% with >= 70% concentration",
                )
            )
        return findings

    @staticmethod
    def _weight_findings(filename: str, weights: weight_stats.WeightReport) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if weights.nan_tensors or weights.inf_tensors:
            findings.append(
                make_finding(
                    finding_id="MOD-NON-FINITE-WEIGHTS",
                    category="MODEL",
                    severity="HIGH",
                    confidence=1.0,
                    affected_asset=f"{len(weights.nan_tensors) + len(weights.inf_tensors)} tensors",
                    explanation=(
                        "Parameter tensors contain NaN or Inf values. The checkpoint will produce "
                        "undefined outputs and is not fit for deployment regardless of any other finding."
                    ),
                    evidence={"nanTensors": weights.nan_tensors[:10], "infTensors": weights.inf_tensors[:10]},
                    recommendation="Reject the checkpoint; the training run diverged or the transfer was corrupted.",
                    detector="modelscan.weight_stats.analyse_weights",
                    threshold="any non-finite parameter value",
                )
            )

        if weights.dead_tensors:
            findings.append(
                make_finding(
                    finding_id="MOD-DEAD-PARAMETERS",
                    category="MODEL",
                    severity="MEDIUM",
                    confidence=0.85,
                    affected_asset=f"{len(weights.dead_tensors)} tensors",
                    explanation=(
                        f"{len(weights.dead_tensors)} weight tensors are constant. An untrained or "
                        "zeroed layer in a supposedly converged checkpoint indicates a truncated "
                        "transfer or a hand-edited file."
                    ),
                    evidence={"tensors": weights.dead_tensors[:15]},
                    recommendation="Verify the checkpoint against the vendor's published digest and training log.",
                    detector="modelscan.weight_stats.analyse_weights",
                    threshold="std == 0 on a non-bias tensor with > 64 elements",
                )
            )

        if weights.outlier_tensors:
            findings.append(
                make_finding(
                    finding_id="MOD-OUTLIER-NEURONS",
                    category="MODEL",
                    severity="MEDIUM",
                    confidence=0.6,
                    affected_asset=f"{len(weights.outlier_tensors)} tensors",
                    explanation=(
                        "Some layers contain output channels whose magnitude sits far outside their "
                        "own layer's distribution. Backdoor implantation by direct weight editing "
                        "concentrates its change in a small number of neurons, so this is worth an "
                        "analyst's attention -- though unusual statistics alone are not proof of malice."
                    ),
                    evidence={"tensors": weights.outlier_tensors[:15]},
                    recommendation="Correlate with the trigger-inversion result; investigate if both fire on the same model.",
                    detector="modelscan.weight_stats.analyse_weights",
                    threshold="modified z-score > 8 on per-channel L2 norm",
                    references=["Liu et al., TrojanNN (NDSS 2018)"],
                )
            )

        if weights.extreme_tensors:
            findings.append(
                make_finding(
                    finding_id="MOD-EXTREME-MAGNITUDE",
                    category="MODEL",
                    severity="LOW",
                    confidence=0.7,
                    affected_asset=f"{len(weights.extreme_tensors)} tensors",
                    explanation="Parameter magnitudes exceed 1e4, which is outside the range of a normally converged vision model.",
                    evidence={"tensors": weights.extreme_tensors[:15]},
                    recommendation="Confirm the checkpoint is post-training and not a mid-divergence snapshot.",
                    detector="modelscan.weight_stats.analyse_weights",
                    threshold="|value| > 1e4",
                )
            )

        return findings

    @staticmethod
    def _compose_limitations(
        mode: AnalysisMode,
        cleanse: neural_cleanse.NeuralCleanseReport,
        battery: battery_module.BatteryReport,
        resolution_note: str = "",
    ) -> str:
        parts = [f"Access obtained: {mode.value}."]
        if resolution_note:
            parts.append(resolution_note)
        if mode == AnalysisMode.WHITE_BOX:
            parts.append(
                "Parameters were loaded strictly into a matching architecture, so the executed graph "
                "is the submitted model."
            )
        else:
            parts.append(
                "The model was not executed, so every behavioural statement is unavailable rather "
                "than negative."
            )
        if cleanse.limitation:
            parts.append(cleanse.limitation)
        if battery.limitation:
            parts.append(battery.limitation)
        return " ".join(parts)

    @staticmethod
    def _result(
        base: dict[str, Any],
        *,
        findings: list[dict[str, Any]],
        mode: AnalysisMode,
        status: str | None,
        framework: str,
        architecture: str,
        risk: float,
        risk_breakdown: dict[str, float],
        limitations: str,
        parameter_count: int | None = None,
        backdoor_confidence: float = 0.0,
        started: float = 0.0,
        **extra: Any,
    ) -> dict[str, Any]:
        ordered = sort_findings(findings)
        if status is None:
            if any(f["severity"] == "CRITICAL" for f in ordered):
                status = "DETECTED"
            elif any(f["severity"] == "HIGH" for f in ordered):
                status = "DETECTED"
            elif any(f["severity"] == "MEDIUM" for f in ordered):
                status = "SUSPICIOUS"
            else:
                status = "NOT DETECTED"

        severity = ordered[0]["severity"] if ordered else "INFO"
        confidence = ordered[0]["confidence"] if ordered else 0.95

        payload = {
            **base,
            "framework": framework,
            "architecture": architecture,
            "parameterCount": parameter_count,
            "analysisMode": mode.value,
            "status": status,
            "severity": severity,
            "confidence": confidence,
            "backdoorConfidence": round(backdoor_confidence, 4),
            "behavioralAnalysis": _summarise_behaviour(extra.get("battery")),
            "backdoorAnalysis": _summarise_backdoor(extra.get("neural_cleanse"), backdoor_confidence),
            "evidence": {
                "sha256": base["sha256"],
                "framework": framework,
                "architecture": architecture,
                "parameterCount": parameter_count,
                "analysisMode": mode.value,
                **{k: v for k, v in extra.items() if k in {"pickle_audit", "weights", "onnx", "safetensors"}},
            },
            "pickleAudit": extra.get("pickle_audit"),
            "torchInspection": extra.get("torch"),
            "onnxInspection": extra.get("onnx"),
            "onnxRuntime": extra.get("onnx_runtime"),
            "safetensorsInfo": extra.get("safetensors"),
            "weightStatistics": extra.get("weights"),
            "behaviouralBattery": extra.get("battery"),
            "neuralCleanse": extra.get("neural_cleanse"),
            "coverage": extra.get("coverage", []),
            "limitations": limitations,
            "riskBreakdown": risk_breakdown,
            "modelRisk": risk,
            "findings": ordered,
            "analysisDurationSeconds": round(time.perf_counter() - started, 3) if started else 0.0,
        }
        return payload


def _summarise_behaviour(battery: dict[str, Any] | None) -> str:
    if not battery or not battery.get("ran"):
        return (
            "Behavioural battery not run: the model could not be executed. No behavioural "
            "conclusion is available."
        )
    entropy = battery.get("cleanPredictionEntropy", 0.0)
    lines = [
        f"Clean reference battery produced a prediction entropy of {entropy:.2f} bits across "
        f"{battery.get('classCount', 0)} classes."
    ]
    for result in battery.get("batteries", []):
        lines.append(
            f"{result['name']}: {result['flipRate']:.1%} of inputs changed prediction, "
            f"{result['flipConcentration']:.1%} concentrated on class {result['targetClass']} "
            f"-> {result['verdict']}."
        )
    return " ".join(lines)


def _summarise_backdoor(cleanse: dict[str, Any] | None, fused: float) -> str:
    if not cleanse or not cleanse.get("ran"):
        return (
            "Trigger inversion not run: white-box access was unavailable. This is a coverage gap, "
            "not a negative result."
        )
    flagged = cleanse.get("flaggedClasses") or []
    if flagged:
        return (
            f"Neural Cleanse flagged class(es) {flagged} with a maximum MAD anomaly index of "
            f"{cleanse.get('maxAnomalyIndex', 0):.2f} against a threshold of "
            f"{cleanse.get('anomalyIndexThreshold')}. Fused backdoor confidence across the trigger "
            f"inversion and behavioural battery: {fused:.0%}."
        )
    return (
        f"Neural Cleanse inverted {cleanse.get('classesScanned', 0)} of "
        f"{cleanse.get('classesTotal', 0)} classes; the maximum MAD anomaly index was "
        f"{cleanse.get('maxAnomalyIndex', 0):.2f}, below the "
        f"{cleanse.get('anomalyIndexThreshold')} detection threshold. No patch-trigger backdoor was "
        "found within the method's stated assumptions."
    )


__all__ = ["ModelAnalyzer"]
