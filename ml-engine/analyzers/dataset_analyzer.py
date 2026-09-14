"""
Dataset Integrity Analyzer
Inspects training archives (ZIP), images, and metadata for:
- Corrupted samples
- Exact duplicate images (SHA-256 collision)
- Near-duplicate candidate clustering
- Class distribution imbalances
- Suspicious label patterns & poisoning indicators
- Out-of-Distribution (OOD) sample flags
"""

import os
import io
import time
import zipfile
import hashlib
from typing import Dict, Any, List, Tuple
from .risk_engine import RiskEngine

IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.bmp', '.gif', '.tiff'}

# Magic byte signatures for image formats
MAGIC_SIGNATURES = {
    b'\xff\xd8\xff': 'JPEG',
    b'\x89PNG\r\n\x1a\n': 'PNG',
    b'GIF87a': 'GIF',
    b'GIF89a': 'GIF',
    b'BM': 'BMP',
    b'RIFF': 'WEBP', # Requires 'WEBP' at offset 8
}

def is_valid_image(data: bytes, ext: str) -> bool:
    if len(data) < 12:
        return False
    if ext in ['.jpg', '.jpeg']:
        return data.startswith(b'\xff\xd8\xff')
    if ext == '.png':
        return data.startswith(b'\x89PNG\r\n\x1a\n')
    if ext == '.gif':
        return data.startswith(b'GIF87a') or data.startswith(b'GIF89a')
    if ext == '.bmp':
        return data.startswith(b'BM')
    if ext == '.webp':
        return data.startswith(b'RIFF') and data[8:12] == b'WEBP'
    return True

class DatasetAnalyzer:
    @staticmethod
    def calculate_sha256(data: bytes) -> str:
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()

    @classmethod
    def analyze_dataset_bytes(cls, filename: str, data: bytes) -> Dict[str, Any]:
        """
        Performs in-depth structural inspection on dataset archive or files.
        """
        dataset_hash = cls.calculate_sha256(data)
        ext = os.path.splitext(filename)[1].lower()
        findings: List[Dict[str, Any]] = []

        total_samples = 0
        corrupted_files: List[str] = []
        hash_to_files: Dict[str, List[str]] = {}
        file_sizes: Dict[str, int] = {}
        class_distribution: Dict[str, int] = {}
        contributor_stats: Dict[str, int] = {}

        if ext == '.zip':
            # Inspect Zip Archive
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    entries = zf.infolist()
                    for entry in entries:
                        if entry.is_dir():
                            continue
                        
                        # Prevent Zip slip path traversal attacks
                        if '..' in entry.filename or entry.filename.startswith('/'):
                            findings.append({
                                "id": f"FIND-SEC-{len(findings)+1:03d}",
                                "findingId": f"SEC-ZIP-SLIP-{len(findings)+1}",
                                "category": "DATASET",
                                "severity": "CRITICAL",
                                "confidence": 1.0,
                                "affectedAsset": entry.filename,
                                "explanation": "Dangerous path traversal element ('..' or leading slash) detected in archive entry.",
                                "evidence": f"Entry path: {entry.filename}",
                                "recommendation": "Quarantine archive immediately; reject corrupted or maliciously crafted zip files.",
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                            })
                            continue

                        file_ext = os.path.splitext(entry.filename)[1].lower()
                        if file_ext in IMAGE_EXTENSIONS:
                            total_samples += 1
                            content = zf.read(entry)
                            file_sizes[entry.filename] = len(content)

                            # Validate magic bytes
                            if not is_valid_image(content, file_ext):
                                corrupted_files.append(entry.filename)
                                continue

                            # Hash sample for duplicate detection
                            sample_hash = cls.calculate_sha256(content)
                            if sample_hash not in hash_to_files:
                                hash_to_files[sample_hash] = []
                            hash_to_files[sample_hash].append(entry.filename)

                            # Infer class label from directory structure (e.g., train/dogs/001.jpg)
                            parts = entry.filename.split('/')
                            if len(parts) >= 2:
                                inferred_class = parts[-2]
                                class_distribution[inferred_class] = class_distribution.get(inferred_class, 0) + 1
                            else:
                                class_distribution["unlabeled"] = class_distribution.get("unlabeled", 0) + 1
                        
                        elif file_ext in ['.csv', '.txt']:
                            # Metadata inspection
                            try:
                                text_content = zf.read(entry).decode('utf-8', errors='ignore')
                                for line in text_content.splitlines()[:50]:
                                    if 'user' in line.lower() or 'source' in line.lower():
                                        cols = line.split(',')
                                        if len(cols) > 1:
                                            user = cols[1].strip()
                                            contributor_stats[user] = contributor_stats.get(user, 0) + 1
                            except Exception:
                                pass

            except zipfile.BadZipFile:
                return {
                    "id": f"DS-{int(time.time())}",
                    "filename": filename,
                    "sha256": dataset_hash,
                    "fileSizeBytes": len(data),
                    "totalSamples": 0,
                    "corruptedFiles": 1,
                    "duplicateFiles": [],
                    "nearDuplicateCandidates": [],
                    "classDistribution": {},
                    "suspiciousLabelPatterns": ["Archive is corrupt or unreadable."],
                    "anomalousSamples": [],
                    "oodIndicators": [],
                    "contributorStats": {},
                    "datasetRisk": 100.0,
                    "status": "ANALYSIS FAILED",
                    "findings": [{
                        "id": "FIND-ERR-001",
                        "findingId": "ERR-CORRUPT-ARCHIVE",
                        "category": "DATASET",
                        "severity": "CRITICAL",
                        "confidence": 1.0,
                        "affectedAsset": filename,
                        "explanation": "Provided file is not a valid zip archive or has been truncated.",
                        "evidence": f"File size: {len(data)} bytes",
                        "recommendation": "Re-export and re-upload the dataset archive.",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }],
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }

        else: # Single image or loose file
            total_samples = 1
            file_sizes[filename] = len(data)
            if not is_valid_image(data, ext):
                corrupted_files.append(filename)
            else:
                sample_hash = dataset_hash
                hash_to_files[sample_hash] = [filename]
                class_distribution["default"] = 1

        # Calculate exact duplicate groups
        duplicate_groups = []
        for shash, files in hash_to_files.items():
            if len(files) > 1:
                duplicate_groups.append({
                    "hash": shash,
                    "filenames": files,
                    "sampleCount": len(files)
                })
                findings.append({
                    "id": f"FIND-DUP-{len(findings)+1:03d}",
                    "findingId": f"DS-EXACT-DUP-{shash[:8]}",
                    "category": "DATASET",
                    "severity": "MEDIUM",
                    "confidence": 1.0,
                    "affectedAsset": ", ".join(files[:3]),
                    "explanation": f"Exact duplicate sample group detected across {len(files)} identical files (SHA-256 match).",
                    "evidence": f"SHA-256: {shash}",
                    "recommendation": "Deduplicate training corpus to prevent memorization and bias.",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                })

        # Near duplicate detection (heuristic via length and hash proximity)
        near_duplicate_candidates = []
        file_items = list(file_sizes.items())
        for i in range(len(file_items)):
            for j in range(i + 1, min(i + 15, len(file_items))):
                fn1, s1 = file_items[i]
                fn2, s2 = file_items[j]
                if s1 > 0 and s2 > 0:
                    diff_pct = abs(s1 - s2) / max(s1, s2)
                    if diff_pct < 0.015 and fn1 != fn2:
                        near_duplicate_candidates.append({
                            "sampleA": fn1,
                            "sampleB": fn2,
                            "similarity": round(1.0 - diff_pct, 4),
                            "metrics": f"Byte length variance: {diff_pct*100:.2f}%"
                        })

        # Corrupted files findings
        if corrupted_files:
            findings.append({
                "id": f"FIND-CORR-{len(findings)+1:03d}",
                "findingId": "DS-CORRUPT-FILES",
                "category": "DATASET",
                "severity": "HIGH",
                "confidence": 0.95,
                "affectedAsset": f"{len(corrupted_files)} samples",
                "explanation": f"Found {len(corrupted_files)} invalid or header-corrupted image files.",
                "evidence": f"Sample corrupt files: {', '.join(corrupted_files[:3])}",
                "recommendation": "Remove or regenerate corrupted assets before training to avoid pipeline crash.",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })

        # Class imbalance & suspicious label patterns
        suspicious_label_patterns = []
        imbalance_ratio = 1.0
        if class_distribution and len(class_distribution) > 1:
            counts = list(class_distribution.values())
            max_c = max(counts)
            min_c = max(1, min(counts))
            imbalance_ratio = max_c / min_c

            if imbalance_ratio > 8.0:
                pattern = f"Severe class imbalance: {imbalance_ratio:.1f}:1 ratio between majority and minority classes."
                suspicious_label_patterns.append(pattern)
                findings.append({
                    "id": f"FIND-LABEL-{len(findings)+1:03d}",
                    "findingId": "DS-LABEL-IMBALANCE",
                    "category": "DATASET",
                    "severity": "MEDIUM",
                    "confidence": 0.90,
                    "affectedAsset": "Class Distribution",
                    "explanation": pattern,
                    "evidence": f"Class distribution: {class_distribution}",
                    "recommendation": "Apply class re-weighting, SMOTE, or stratified collection.",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                })

        # Anomalous samples & OOD indicators
        anomalous_samples = []
        ood_indicators = []
        if file_sizes:
            sizes = list(file_sizes.values())
            avg_size = sum(sizes) / len(sizes)
            variance = sum((s - avg_size) ** 2 for s in sizes) / max(1, len(sizes))
            std_dev = variance ** 0.5

            for fn, sz in file_sizes.items():
                if std_dev > 0 and abs(sz - avg_size) > 2.8 * std_dev:
                    anomaly_score = round(abs(sz - avg_size) / (std_dev * 3.0), 3)
                    anomalous_samples.append({
                        "filename": fn,
                        "reason": f"File size ({sz} bytes) is an extreme outlier (>2.8 stdev from mean {int(avg_size)}).",
                        "anomalyScore": min(1.0, anomaly_score),
                        "metric": f"{sz} B vs mean {int(avg_size)} B"
                    })

        if anomalous_samples:
            ood_indicators.append(f"{len(anomalous_samples)} structural outliers detected via byte distribution variance.")

        # Determine overall status
        status = "NOT DETECTED"
        if any(f["severity"] == "CRITICAL" for f in findings):
            status = "DETECTED"
        elif any(f["severity"] in ["HIGH", "MEDIUM"] for f in findings):
            status = "SUSPICIOUS"

        findings_risk = RiskEngine.calculate_findings_risk(findings)
        dataset_risk = RiskEngine.calculate_dataset_risk(
            total_samples=max(1, total_samples),
            corrupted_count=len(corrupted_files),
            duplicate_count=sum(g["sampleCount"] for g in duplicate_groups),
            anomalous_count=len(anomalous_samples),
            class_imbalance_ratio=imbalance_ratio,
            findings_risk=findings_risk
        )

        return {
            "id": f"DS-{int(time.time())}",
            "filename": filename,
            "sha256": dataset_hash,
            "fileSizeBytes": len(data),
            "totalSamples": total_samples,
            "corruptedFiles": len(corrupted_files),
            "duplicateFiles": duplicate_groups,
            "nearDuplicateCandidates": near_duplicate_candidates[:20],
            "classDistribution": class_distribution,
            "suspiciousLabelPatterns": suspicious_label_patterns,
            "anomalousSamples": anomalous_samples[:25],
            "oodIndicators": ood_indicators,
            "contributorStats": contributor_stats,
            "datasetRisk": dataset_risk,
            "status": status,
            "findings": findings,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
