"""Attack-coverage and limitation disclosure matrices.

The problem statement asks for "documented attack coverage, limitations". This module
produces that document as data rather than prose, so the console can render it and an
assessor can diff it between runs.

The honest half matters more than the reassuring half: a matrix that marks everything
covered is worthless. Each row states the method actually used, the confidence it earns
under the current runtime configuration, and the specific condition under which it
fails. Rows degrade automatically -- if the feature backbone was not staged, the
embedding-dependent rows drop their confidence and say why.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.models import CoverageEntry

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ingest.parsers import DatasetLayout
    from vision.embeddings import BackboneInfo
    from vision.triggers import TriggerReport


def dataset_coverage(
    backbone: "BackboneInfo",
    layout: "DatasetLayout",
    triggers: "TriggerReport",
) -> list[CoverageEntry]:
    """Coverage matrix for the dataset engine under the current configuration."""
    embedding_ready = backbone.source in {"LOCAL_WEIGHTS", "DOWNLOADED"}
    embedding_conf = backbone.confidence_multiplier
    has_labels = bool(layout.class_names) and layout.format.value not in {"FLAT_IMAGE_SET", "UNKNOWN"}

    return [
        CoverageEntry(
            threat="Exact duplicate flooding",
            technique="Byte-identical resubmission",
            covered=True,
            confidence=1.0,
            method="SHA-256 grouping over every decoded sample.",
            limitation="None. A byte-identical duplicate is detected with certainty.",
        ),
        CoverageEntry(
            threat="Near-duplicate flooding",
            technique="Rescale / recompress / crop resubmission",
            covered=True,
            confidence=0.95 if embedding_ready else 0.72,
            method=(
                "DCT perceptual hash with a BK-tree radius query (Hamming <= 5), confirmed by "
                "ResNet-18 embedding cosine > 0.98."
                if embedding_ready
                else "DCT perceptual hash with a BK-tree radius query (Hamming <= 5), corroborated "
                "by difference-hash agreement. Embedding confirmation is unavailable."
            ),
            limitation=(
                "Heavy crops, large rotations and aggressive colour regrading move a sample beyond "
                "the pHash radius. Semantically identical scenes shot from a different angle are "
                "not duplicates and are correctly not flagged."
                + ("" if embedding_ready else " Without a staged backbone the precision stage is absent, so expect more false positives on flat imagery.")
            ),
        ),
        CoverageEntry(
            threat="Label flipping / systematic mislabelling",
            technique="Targeted class-pair annotation inversion",
            covered=has_labels and embedding_conf > 0,
            confidence=0.88 * embedding_conf if has_labels else 0.0,
            method=(
                "k-NN clean-feature cross-validation in embedding space with directed class-pair "
                "flow analysis to separate targeted flipping from diffuse annotation noise."
            ),
            limitation=(
                "Requires at least two classes with sufficient samples. Classes that genuinely "
                "overlap in feature space (for example civilian and military variants of the same "
                "chassis) raise false positives. Instance-level detection labels are approximated "
                "to image level for detection corpora."
                if has_labels
                else "No usable class labels were found in this submission, so the check did not run."
            ),
            references=["Northcutt et al., Confident Learning (JAIR 2021)"],
        ),
        CoverageEntry(
            threat="Backdoor trigger injection (static patch)",
            technique="BadNets, corner stamps, checkerboard patches",
            covered=triggers.consensus_available,
            confidence=0.93 if triggers.consensus_available else 0.45,
            method=(
                "Per-class median residual with modified z-score outlier selection and spatial "
                "consensus clustering; the shared trigger pattern is recovered and returned."
            ),
            limitation=(
                "Requires at least 12 samples per class to build a stable median. A poisoning rate "
                "near 50% of a class corrupts the median itself and suppresses the residual."
                if triggers.consensus_available
                else "Too few samples for consensus analysis; only single-image screening ran."
            ),
            references=["Gu et al., BadNets (2017)"],
        ),
        CoverageEntry(
            threat="Backdoor trigger injection (blended)",
            technique="Low-amplitude global overlay",
            covered=triggers.consensus_available,
            confidence=0.70 if triggers.consensus_available else 0.3,
            method="Residual magnitude analysis against the class median with family classification.",
            limitation=(
                "Blended triggers below roughly 5% alpha approach the sensor-noise floor and are not "
                "reliably separable from compression artifacts at image level."
            ),
            references=["Chen et al., Targeted Backdoor Attacks (2017)"],
        ),
        CoverageEntry(
            threat="Input-aware / warping backdoors",
            technique="WaNet, BppAttack, sample-specific triggers",
            covered=False,
            confidence=0.0,
            method="Not detectable from imagery: the perturbation differs per sample by construction.",
            limitation=(
                "No cross-sample consensus exists for these families, so dataset-side screening "
                "cannot see them. They are addressed only by the model-side trigger inversion and "
                "behavioural battery, and only when the checkpoint can be loaded white-box."
            ),
            references=["Nguyen & Tran, WaNet (ICLR 2021)"],
        ),
        CoverageEntry(
            threat="Clean-label poisoning",
            technique="Feature-collision, Sleeper Agent",
            covered=False,
            confidence=0.0,
            method="Not covered by dataset-side screening.",
            limitation=(
                "Clean-label attacks keep the label correct and the perturbation imperceptible, so "
                "neither the label-consistency nor the trigger detector fires. Detection requires "
                "gradient-level analysis against the training run itself, which is out of scope for "
                "an inspection layer that never trains."
            ),
            references=["Shafahi et al., Poison Frogs (NeurIPS 2018)"],
        ),
        CoverageEntry(
            threat="Out-of-distribution blind spots",
            technique="Domain padding, sensor mismatch",
            covered=embedding_conf > 0,
            confidence=0.85 * embedding_conf,
            method="Mahalanobis distance to class centroids with Ledoit-Wolf shrunk pooled covariance.",
            limitation=(
                "Outliers are relative to the submitted corpus, not an external reference. A corpus "
                "that is uniformly out-of-domain reports few internal outliers."
            ),
            references=["Lee et al., NeurIPS 2018"],
        ),
        CoverageEntry(
            threat="Annotation manipulation",
            technique="Dangling ids, undeclared categories, out-of-range boxes",
            covered=layout.format.value in {"COCO_JSON", "YOLO"},
            confidence=0.97 if layout.format.value in {"COCO_JSON", "YOLO"} else 0.0,
            method="Schema conformance checking against the COCO and YOLO specifications.",
            limitation=(
                "Only structural validity is checked. An annotation that is well-formed but wrong is "
                "the label-consistency detector's problem, not this one's."
                if layout.format.value in {"COCO_JSON", "YOLO"}
                else "No COCO or YOLO manifest present in this submission."
            ),
        ),
        CoverageEntry(
            threat="Archive-level supply chain attack",
            technique="Zip Slip, decompression bomb, symlink escape",
            covered=True,
            confidence=1.0,
            method="Path normalisation, per-entry and cumulative size ceilings, ratio ceiling, link rejection.",
            limitation="Nothing is ever written to disk from an archive, so traversal is reported rather than merely blocked.",
            references=["CWE-22", "CWE-409", "CWE-59"],
        ),
        CoverageEntry(
            threat="Evaluation contamination",
            technique="Duplicate samples spanning train/test splits",
            covered=True,
            confidence=0.9,
            method="Duplicate clusters cross-referenced against conventional split directory names.",
            limitation="Splits defined in an external manifest rather than by directory are not recognised.",
        ),
    ]


def model_coverage(
    *,
    executed: bool,
    architecture_recovered: bool,
    neural_cleanse_ran: bool,
    serialization_verdict: str,
    format_name: str,
) -> list[CoverageEntry]:
    """Coverage matrix for the model engine, reflecting the access actually obtained."""
    return [
        CoverageEntry(
            threat="Malicious deserialisation",
            technique="pickle REDUCE / GLOBAL arbitrary code execution",
            covered=True,
            confidence=0.98,
            method=(
                "Full opcode disassembly against a symbol allowlist, with broken streams and "
                "non-standard containers treated as hostile."
            ),
            limitation=(
                "A payload hidden in a container we deliberately do not unpack (7z, RAR) is reported "
                "as suspicious rather than decoded. Adding those extractors would enlarge the node's "
                "own attack surface for no analytical gain."
            ),
            references=["ReversingLabs nullifAI (2025)", "MITRE ATLAS AML.T0010"],
        ),
        CoverageEntry(
            threat="Model substitution",
            technique="Swapped checkpoint with matching filename",
            covered=True,
            confidence=1.0,
            method="SHA-256 digest of the checkpoint bytes, bound into every inference record.",
            limitation="Detects substitution only against a previously recorded digest; a first submission has no baseline to compare with.",
        ),
        CoverageEntry(
            threat="Structural trojanisation",
            technique="Injected subgraphs, orphaned nodes, unexpected operators",
            covered=architecture_recovered or format_name == "ONNX",
            confidence=0.85 if (architecture_recovered or format_name == "ONNX") else 0.2,
            method="Graph or state-dict enumeration with operator allowlisting and topology checks.",
            limitation=(
                "Requires a parseable graph. A state dict alone carries no topology, so only "
                "parameter-level anomalies are visible."
                if not architecture_recovered
                else "Semantically equivalent but malicious weight values are not structural and are covered by the behavioural battery instead."
            ),
        ),
        CoverageEntry(
            threat="Backdoor (patch trigger)",
            technique="BadNets, TrojanNN, blended",
            covered=neural_cleanse_ran,
            confidence=0.86 if neural_cleanse_ran else 0.0,
            method=(
                "Neural Cleanse optimisation-based trigger inversion per class (seeded, so "
                "reproducible), with a MAD-normalised anomaly index over the recovered L1 mask "
                "norms. Corroborative only: it earns a confirmed-backdoor finding solely when it "
                "agrees with the behavioural battery on the same target class."
                if neural_cleanse_ran
                else "Not run: the checkpoint could not be loaded and executed (ONNX has no gradients "
                "for mask optimisation; a state dict without a recoverable architecture cannot execute)."
            ),
            limitation=(
                "Neural Cleanse assumes a small, static, input-agnostic trigger and a single target "
                "class. All-to-all backdoors, large triggers and input-aware attacks evade it. On "
                "synthetic air-gapped imagery it also false-positives at a rate that can rank a clean "
                "model's most-invertible class above a real backdoor's target, so an uncorroborated "
                "inversion is reported as a LOW lead, never a detection."
                if neural_cleanse_ran
                else "White-box access was not obtained, so no behavioural conclusion can be drawn. "
                "Absence of a finding here is not evidence of absence of a backdoor."
            ),
            references=["Wang et al., Neural Cleanse (IEEE S&P 2019)"],
        ),
        CoverageEntry(
            threat="Weight-level anomaly",
            technique="NaN/Inf injection, outlier neurons, rank collapse",
            covered=True,
            confidence=0.9,
            method="Per-tensor moment, sparsity, outlier-fraction and spectral statistics over every parameter.",
            limitation="Distinguishes anomalous from typical, not malicious from benign; unusual statistics warrant review rather than condemnation.",
        ),
        CoverageEntry(
            threat="Behavioural backdoor confirmation",
            technique="Attack success rate under a synthetic trigger battery",
            covered=executed,
            confidence=0.8 if executed else 0.0,
            method=(
                "Clean reference battery plus BadNets, blended and corner-stamp trigger batteries, "
                "measuring label-flip rate and target concentration against the clean baseline. The "
                "primary behavioural detector; runs on TorchScript/state-dict models and on ONNX "
                "models via onnxruntime forward inference, at a resolution selected by measurement."
                if executed
                else "Not run: model execution was unavailable or disabled (for ONNX, onnxruntime is "
                "not installed on this node)."
            ),
            limitation=(
                "The battery uses synthetic imagery because an air-gapped node has no held-out "
                "operational data. It therefore measures trigger *responsiveness*, not accuracy on "
                "the real mission distribution. A high flip rate is strong evidence; a low one only "
                "rules out the trigger families in the battery."
            ),
        ),
        CoverageEntry(
            threat="Serialization format risk",
            technique="Legacy pickle checkpoint",
            covered=True,
            confidence=1.0,
            method=f"Container identification: {format_name}, verdict {serialization_verdict}.",
            limitation="safetensors or ONNX submission eliminates this class of risk entirely and should be required of vendors.",
        ),
    ]


__all__ = ["dataset_coverage", "model_coverage"]
