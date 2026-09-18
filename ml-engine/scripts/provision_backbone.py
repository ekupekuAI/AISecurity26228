"""Stage the reference feature backbone for an air-gapped deployment.

Run this once on a machine with network access, then ship ml-engine/assets/ with the
bundle. The engine refuses to download weights at runtime, so this is the only supported
way to give an air-gapped node a pretrained backbone.

    python ml-engine/scripts/provision_backbone.py

Without it the engine still runs: embedding analytics fall back to a deterministically
seeded random-initialised ResNet-18 and every affected finding is reported at reduced
confidence with an explicit limitation. That is a degraded mode, not a silent one.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE_ROOT))


def main() -> int:
    try:
        import torch
        from torchvision.models import ResNet18_Weights, resnet18
    except ImportError as exc:
        print(f"torch/torchvision are required to provision the backbone: {exc}", file=sys.stderr)
        return 1

    target = ENGINE_ROOT / "assets" / "backbone_resnet18.pt"
    target.parent.mkdir(parents=True, exist_ok=True)

    print("Downloading ImageNet-1k ResNet-18 weights ...")
    model = resnet18(weights=ResNet18_Weights.IMAGENET1K_V1)
    state = model.state_dict()

    torch.save(state, target)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()

    print(f"Staged: {target}")
    print(f"SHA-256: {digest}")
    print(f"Size: {target.stat().st_size / 1e6:.1f} MB")
    print()
    print("Record this digest in your deployment manifest and verify it on the air-gapped")
    print("node before first use. The engine reports the digest it loaded in /health.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
