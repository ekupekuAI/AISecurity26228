"""Dataset layout detection and annotation integrity checking.

Three layouts cover essentially all operational CV submissions:

* **COCO JSON** -- detection/segmentation, one manifest describing images, categories
  and annotations by id.
* **YOLO** -- one ``.txt`` per image holding ``class cx cy w h`` in normalised
  coordinates, with an optional ``data.yaml`` naming the classes.
* **ImageFolder** -- class identity carried by the parent directory name.

Parsing them is not just a convenience: annotation files are themselves an attack
surface. A COCO manifest can reference image ids that do not exist, assign two
annotations to the same object, or carry boxes with negative area; a YOLO label can put
coordinates outside [0,1] or name a class index the manifest never declared. Each of
those either crashes a training pipeline or silently corrupts it, so every structural
defect found here is reported as evidence rather than swallowed.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from vision.imaging import IMAGE_EXTENSIONS


class DatasetFormat(str, Enum):
    COCO = "COCO_JSON"
    YOLO = "YOLO"
    IMAGE_FOLDER = "IMAGE_FOLDER"
    FLAT = "FLAT_IMAGE_SET"
    UNKNOWN = "UNKNOWN"


@dataclass
class AnnotationDefect:
    kind: str
    location: str
    detail: str
    severity: str = "MEDIUM"

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "location": self.location, "detail": self.detail, "severity": self.severity}


@dataclass
class DatasetLayout:
    """What the archive turned out to be, and the labels it yields."""

    format: DatasetFormat = DatasetFormat.UNKNOWN
    labels: dict[str, str] = field(default_factory=dict)  # image path -> class label
    class_names: list[str] = field(default_factory=list)
    annotation_count: int = 0
    boxes_per_image: dict[str, int] = field(default_factory=dict)
    defects: list[AnnotationDefect] = field(default_factory=list)
    manifest_files: list[str] = field(default_factory=list)
    unlabelled_images: list[str] = field(default_factory=list)
    orphan_labels: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format.value,
            "classNames": self.class_names,
            "classCount": len(self.class_names),
            "annotationCount": self.annotation_count,
            "labelledImages": len(self.labels),
            "unlabelledImages": len(self.unlabelled_images),
            "unlabelledExamples": self.unlabelled_images[:12],
            "orphanLabelFiles": len(self.orphan_labels),
            "orphanLabelExamples": self.orphan_labels[:12],
            "manifestFiles": self.manifest_files[:8],
            "defects": [d.to_dict() for d in self.defects[:60]],
            "defectCount": len(self.defects),
            "notes": self.notes,
        }


def _normalise(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _stem(path: str) -> str:
    base = posixpath.basename(_normalise(path))
    return base.rsplit(".", 1)[0] if "." in base else base


def detect_and_parse(
    image_paths: list[str],
    text_files: dict[str, bytes],
) -> DatasetLayout:
    """Identify the layout and extract per-image class labels."""
    layout = DatasetLayout()
    if not image_paths and not text_files:
        layout.notes.append("Archive contained no images and no annotation files.")
        return layout

    coco_manifests = {
        name: data
        for name, data in text_files.items()
        if name.lower().endswith(".json") and b'"annotations"' in data[:200_000]
    }
    if coco_manifests:
        return _parse_coco(image_paths, coco_manifests, text_files, layout)

    yolo_labels = {
        name: data
        for name, data in text_files.items()
        if name.lower().endswith(".txt") and _looks_like_yolo(data)
    }
    if yolo_labels:
        return _parse_yolo(image_paths, yolo_labels, text_files, layout)

    return _parse_folders(image_paths, layout)


# --- COCO ------------------------------------------------------------------------


def _parse_coco(
    image_paths: list[str],
    manifests: dict[str, bytes],
    text_files: dict[str, bytes],
    layout: DatasetLayout,
) -> DatasetLayout:
    layout.format = DatasetFormat.COCO
    layout.manifest_files = sorted(manifests)

    by_basename: dict[str, list[str]] = defaultdict(list)
    for path in image_paths:
        by_basename[posixpath.basename(_normalise(path))].append(path)

    categories: dict[int, str] = {}
    image_id_to_file: dict[int, str] = {}
    annotation_labels: dict[str, Counter] = defaultdict(Counter)
    box_counts: Counter = Counter()
    seen_annotation_ids: set[int] = set()
    total_annotations = 0

    for manifest_name, blob in manifests.items():
        try:
            document = json.loads(blob.decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            layout.defects.append(
                AnnotationDefect("manifest-unparseable", manifest_name, f"{type(exc).__name__}: {exc}", "HIGH")
            )
            continue

        if not isinstance(document, dict):
            layout.defects.append(
                AnnotationDefect("manifest-shape", manifest_name, "Top-level COCO document is not an object.", "HIGH")
            )
            continue

        for category in document.get("categories") or []:
            if isinstance(category, dict) and "id" in category:
                categories[int(category["id"])] = str(category.get("name", f"class_{category['id']}"))

        declared_images: dict[int, dict[str, Any]] = {}
        for entry in document.get("images") or []:
            if not isinstance(entry, dict) or "id" not in entry:
                continue
            image_id = int(entry["id"])
            declared_images[image_id] = entry
            file_name = str(entry.get("file_name", ""))
            candidates = by_basename.get(posixpath.basename(file_name.replace("\\", "/")), [])
            if candidates:
                image_id_to_file[image_id] = candidates[0]
            elif file_name:
                layout.defects.append(
                    AnnotationDefect(
                        "missing-image",
                        f"{manifest_name}#images[{image_id}]",
                        f"Manifest references '{file_name}' which is absent from the archive.",
                        "MEDIUM",
                    )
                )

        for annotation in document.get("annotations") or []:
            if not isinstance(annotation, dict):
                continue
            total_annotations += 1

            annotation_id = annotation.get("id")
            if isinstance(annotation_id, int):
                if annotation_id in seen_annotation_ids:
                    layout.defects.append(
                        AnnotationDefect(
                            "duplicate-annotation-id",
                            f"{manifest_name}#annotations[{annotation_id}]",
                            "Annotation id repeats; COCO requires uniqueness and downstream "
                            "loaders silently drop one of the pair.",
                            "MEDIUM",
                        )
                    )
                seen_annotation_ids.add(annotation_id)

            image_id = annotation.get("image_id")
            if image_id is None or int(image_id) not in declared_images:
                layout.defects.append(
                    AnnotationDefect(
                        "dangling-annotation",
                        f"{manifest_name}#annotations[{annotation_id}]",
                        f"Annotation targets image_id {image_id}, which is not declared in this manifest.",
                        "HIGH",
                    )
                )
                continue

            category_id = annotation.get("category_id")
            if category_id is not None and int(category_id) not in categories:
                layout.defects.append(
                    AnnotationDefect(
                        "undeclared-category",
                        f"{manifest_name}#annotations[{annotation_id}]",
                        f"category_id {category_id} has no entry in the categories array.",
                        "HIGH",
                    )
                )

            bbox = annotation.get("bbox")
            entry = declared_images[int(image_id)]
            if isinstance(bbox, (list, tuple)) and len(bbox) == 4:
                defect = _check_coco_bbox(bbox, entry)
                if defect:
                    layout.defects.append(
                        AnnotationDefect(
                            "invalid-bbox", f"{manifest_name}#annotations[{annotation_id}]", defect, "MEDIUM"
                        )
                    )

            path = image_id_to_file.get(int(image_id))
            if path is not None:
                box_counts[path] += 1
                if category_id is not None:
                    annotation_labels[path][categories.get(int(category_id), f"class_{category_id}")] += 1

    # An image's label is the category that dominates its annotations. For detection
    # corpora this is an approximation, and we say so.
    for path, counter in annotation_labels.items():
        layout.labels[path] = counter.most_common(1)[0][0]

    layout.class_names = sorted(set(categories.values()))
    layout.annotation_count = total_annotations
    layout.boxes_per_image = dict(box_counts)
    layout.unlabelled_images = sorted(set(image_paths) - set(layout.labels))
    layout.notes.append(
        "Detection corpus: per-image class is the majority category across that image's "
        "annotations. Label-consistency findings are therefore image-level, not instance-level."
    )
    return layout


def _check_coco_bbox(bbox: list[Any], image_entry: dict[str, Any]) -> str | None:
    try:
        x, y, w, h = (float(v) for v in bbox)
    except (TypeError, ValueError):
        return "bbox values are not numeric"
    if w <= 0 or h <= 0:
        return f"non-positive box extent (w={w}, h={h})"
    if x < 0 or y < 0:
        return f"negative box origin (x={x}, y={y})"
    width = image_entry.get("width")
    height = image_entry.get("height")
    if isinstance(width, (int, float)) and isinstance(height, (int, float)) and width > 0 and height > 0:
        if x + w > width + 1 or y + h > height + 1:
            return f"box extends beyond the declared image bounds ({width}x{height})"
    return None


# --- YOLO ------------------------------------------------------------------------

_YOLO_LINE = re.compile(r"^\s*\d+(?:\s+[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?){4,}\s*$")


def _looks_like_yolo(data: bytes) -> bool:
    """A YOLO label file is a handful of `class cx cy w h` rows and nothing else."""
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines or len(lines) > 2000:
        return False
    return all(_YOLO_LINE.match(line) for line in lines[:32])


def _parse_yolo(
    image_paths: list[str],
    label_files: dict[str, bytes],
    text_files: dict[str, bytes],
    layout: DatasetLayout,
) -> DatasetLayout:
    layout.format = DatasetFormat.YOLO

    class_names = _yolo_class_names(text_files, layout)
    layout.manifest_files = [
        name for name in text_files if posixpath.basename(name.lower()) in {"data.yaml", "data.yml", "classes.txt", "obj.names"}
    ]

    images_by_stem: dict[str, list[str]] = defaultdict(list)
    for path in image_paths:
        images_by_stem[_stem(path)].append(path)

    per_image_classes: dict[str, Counter] = defaultdict(Counter)
    box_counts: Counter = Counter()
    total = 0
    max_class_index = -1

    for label_path, blob in label_files.items():
        stem = _stem(label_path)
        targets = images_by_stem.get(stem, [])
        if not targets:
            layout.orphan_labels.append(label_path)

        try:
            text = blob.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            layout.defects.append(AnnotationDefect("label-unreadable", label_path, "not valid UTF-8", "MEDIUM"))
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            parts = line.split()
            total += 1
            try:
                class_index = int(parts[0])
                coordinates = [float(v) for v in parts[1:5]]
            except (ValueError, IndexError):
                layout.defects.append(
                    AnnotationDefect("malformed-label", f"{label_path}:{line_number}", line.strip()[:120], "MEDIUM")
                )
                continue

            max_class_index = max(max_class_index, class_index)

            if class_index < 0:
                layout.defects.append(
                    AnnotationDefect("negative-class", f"{label_path}:{line_number}", f"class index {class_index}", "HIGH")
                )
            if any(value < 0.0 or value > 1.0 for value in coordinates):
                layout.defects.append(
                    AnnotationDefect(
                        "coordinates-out-of-range",
                        f"{label_path}:{line_number}",
                        f"YOLO coordinates must be normalised to [0,1]; got {coordinates}",
                        "MEDIUM",
                    )
                )
            if coordinates[2] <= 0 or coordinates[3] <= 0:
                layout.defects.append(
                    AnnotationDefect(
                        "degenerate-box",
                        f"{label_path}:{line_number}",
                        f"zero or negative extent (w={coordinates[2]}, h={coordinates[3]})",
                        "MEDIUM",
                    )
                )

            name = class_names[class_index] if 0 <= class_index < len(class_names) else f"class_{class_index}"
            for target in targets:
                per_image_classes[target][name] += 1
                box_counts[target] += 1

    if class_names and max_class_index >= len(class_names):
        layout.defects.append(
            AnnotationDefect(
                "class-index-overflow",
                ",".join(layout.manifest_files) or "<no manifest>",
                f"Labels reference class index {max_class_index} but only {len(class_names)} names are declared.",
                "HIGH",
            )
        )

    for path, counter in per_image_classes.items():
        layout.labels[path] = counter.most_common(1)[0][0]

    layout.class_names = class_names or sorted({name for counter in per_image_classes.values() for name in counter})
    layout.annotation_count = total
    layout.boxes_per_image = dict(box_counts)
    layout.unlabelled_images = sorted(set(image_paths) - set(layout.labels))

    if layout.unlabelled_images:
        layout.notes.append(
            f"{len(layout.unlabelled_images)} images have no matching .txt label file. In a YOLO "
            "corpus an unlabelled image is trained as pure background, which is a silent way to "
            "suppress a class."
        )
    return layout


def _yolo_class_names(text_files: dict[str, bytes], layout: DatasetLayout) -> list[str]:
    """Read class names from data.yaml / classes.txt without importing a YAML parser."""
    for name, blob in text_files.items():
        base = posixpath.basename(name.lower())
        if base not in {"data.yaml", "data.yml", "classes.txt", "obj.names"}:
            continue
        try:
            text = blob.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue

        if base in {"classes.txt", "obj.names"}:
            names = [line.strip() for line in text.splitlines() if line.strip()]
            if names:
                return names
            continue

        # data.yaml: `names: [a, b]` inline, or a block list under `names:`.
        inline = re.search(r"^names\s*:\s*\[(.*?)\]", text, re.MULTILINE | re.DOTALL)
        if inline:
            return [item.strip().strip("'\"") for item in inline.group(1).split(",") if item.strip()]

        block = re.search(r"^names\s*:\s*$((?:\n\s*-\s*.+)+)", text, re.MULTILINE)
        if block:
            return [line.strip().lstrip("-").strip().strip("'\"") for line in block.group(1).splitlines() if line.strip()]

        mapping = re.findall(r"^\s*(\d+)\s*:\s*(.+)$", text, re.MULTILINE)
        if mapping:
            ordered = sorted(((int(index), value.strip().strip("'\"")) for index, value in mapping))
            return [value for _, value in ordered]

    layout.notes.append("No YOLO class manifest (data.yaml / classes.txt) found; classes are indexed numerically.")
    return []


# --- ImageFolder -----------------------------------------------------------------


def _parse_folders(image_paths: list[str], layout: DatasetLayout) -> DatasetLayout:
    """Class identity from the immediate parent directory."""
    labels: dict[str, str] = {}
    for path in image_paths:
        parts = _normalise(path).split("/")
        if len(parts) >= 2:
            labels[path] = parts[-2]
        else:
            labels[path] = "unlabelled"

    distinct = {label for label in labels.values() if label != "unlabelled"}
    if len(distinct) >= 2:
        layout.format = DatasetFormat.IMAGE_FOLDER
        layout.class_names = sorted(distinct)
    else:
        layout.format = DatasetFormat.FLAT
        layout.class_names = sorted(set(labels.values()))
        layout.notes.append(
            "Archive is a flat image set with no directory or manifest labels. Label-consistency "
            "checking is unavailable; duplicate, trigger and OOD screening still apply."
        )

    layout.labels = labels
    layout.annotation_count = len(labels)
    return layout


def detect_split_leakage(labels: dict[str, str], duplicate_clusters: list[list[str]]) -> list[dict[str, Any]]:
    """Find duplicate clusters that straddle a train/val/test boundary.

    Test-set contamination inflates reported accuracy without any adversary at all, and
    a contributor can engineer it deliberately. Splits are recognised by the conventional
    directory names.
    """
    split_pattern = re.compile(r"(?:^|/)(train|training|val|valid|validation|test|eval|holdout)(?:/|$)", re.IGNORECASE)
    leaks: list[dict[str, Any]] = []

    for cluster in duplicate_clusters:
        splits: dict[str, list[str]] = defaultdict(list)
        for path in cluster:
            match = split_pattern.search(_normalise(path))
            if match:
                splits[match.group(1).lower()].append(path)
        normalised = {
            {"training": "train", "valid": "val", "validation": "val", "eval": "test", "holdout": "test"}.get(k, k)
            for k in splits
        }
        if len(normalised) > 1:
            leaks.append(
                {
                    "splits": sorted(normalised),
                    "sampleCount": len(cluster),
                    "examples": cluster[:6],
                }
            )
    return leaks


__all__ = [
    "AnnotationDefect",
    "DatasetFormat",
    "DatasetLayout",
    "detect_and_parse",
    "detect_split_leakage",
]
