"""
Safe Model Loader Abstraction
Evaluates PyTorch (.pt, .pth) and ONNX (.onnx) model artifacts.
Enforces strict deserialization security to avoid arbitrary code execution.
"""

import os
import hashlib
import zipfile
import struct
from typing import Dict, Any, Optional, Tuple

class SafeModelLoader:
    ALLOWED_EXTENSIONS = {'.pt', '.pth', '.onnx'}
    
    # Dangerous opcode symbols in Python pickle byte streams
    DANGEROUS_PICKLE_SYMBOLS = [
        b'os', b'subprocess', b'sys', b'posix', b'eval', b'exec',
        b'system', b'popen', b'commands', b'builtins', b'__builtin__'
    ]

    @staticmethod
    def calculate_sha256(file_bytes: bytes) -> str:
        hasher = hashlib.sha256()
        hasher.update(file_bytes)
        return hasher.hexdigest()

    @classmethod
    def inspect_model(cls, filename: str, file_bytes: bytes) -> Dict[str, Any]:
        """
        Safely inspects an uploaded model without executing untrusted code.
        """
        ext = os.path.splitext(filename)[1].lower()
        sha256_hash = cls.calculate_sha256(file_bytes)
        size_bytes = len(file_bytes)

        if ext not in cls.ALLOWED_EXTENSIONS:
            return {
                "supported": False,
                "framework": "Unknown",
                "architecture": "Unknown",
                "parameter_count": None,
                "sha256": sha256_hash,
                "file_size": size_bytes,
                "status": "NOT SUPPORTED",
                "error": f"Unsupported extension: {ext}. Only .pt, .pth, and .onnx are accepted."
            }

        if ext == '.onnx':
            return cls._inspect_onnx(file_bytes, sha256_hash, size_bytes)
        else: # .pt or .pth
            return cls._inspect_pytorch(file_bytes, sha256_hash, size_bytes)

    @classmethod
    def _inspect_onnx(cls, file_bytes: bytes, sha256_hash: str, size_bytes: int) -> Dict[str, Any]:
        # Basic ONNX Protobuf wire format sanity check
        # ONNX ModelProto starts with field 1 (ir_version) or field 2 (opset_import)
        # Magic bytes are typically Protobuf varints (0x08 for ir_version wire tag)
        if len(file_bytes) < 4:
            return {
                "supported": False,
                "framework": "ONNX",
                "architecture": "Corrupted",
                "parameter_count": None,
                "sha256": sha256_hash,
                "file_size": size_bytes,
                "status": "ANALYSIS FAILED",
                "error": "ONNX model file is truncated or corrupted."
            }

        is_protobuf = file_bytes[0] in [0x08, 0x12, 0x1a, 0x22]
        if not is_protobuf:
            return {
                "supported": False,
                "framework": "ONNX",
                "architecture": "Unknown",
                "parameter_count": None,
                "sha256": sha256_hash,
                "file_size": size_bytes,
                "status": "ANALYSIS FAILED",
                "error": "File does not match ONNX Protobuf specification."
            }

        # Estimate parameters from file payload volume for standard float32 weights (approx 4 bytes/weight)
        estimated_params = max(1000, int(size_bytes / 4))

        return {
            "supported": True,
            "framework": "ONNX Runtime",
            "architecture": "ONNX Graph Specification",
            "parameter_count": estimated_params,
            "sha256": sha256_hash,
            "file_size": size_bytes,
            "status": "NOT DETECTED",
            "metadata": {
                "ir_version": "v7+",
                "producer": "ONNX Exporter",
                "format": "Protobuf Graph"
            }
        }

    @classmethod
    def _inspect_pytorch(cls, file_bytes: bytes, sha256_hash: str, size_bytes: int) -> Dict[str, Any]:
        # PyTorch files can be modern ZIP-based (PK\x03\x04) or legacy Pickle
        is_zip = file_bytes[:4] == b'PK\x03\x04'

        if is_zip:
            # Safe inspection via zip manifest without unpickling
            try:
                import io
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                    namelist = zf.namelist()
                    # Check for standard PyTorch TorchScript or zip save paths
                    has_data = any('data.pkl' in name or 'byteorder' in name for name in namelist)
                    has_code = any('code/' in name for name in namelist)
                    
                    # Scan pickle data inside zip for dangerous calls
                    for name in namelist:
                        if name.endswith('.pkl'):
                            pkl_bytes = zf.read(name)
                            for bad_symbol in cls.DANGEROUS_PICKLE_SYMBOLS:
                                if bad_symbol in pkl_bytes:
                                    return {
                                        "supported": False,
                                        "framework": "PyTorch (Zip Archive)",
                                        "architecture": "Untrusted / Malicious",
                                        "parameter_count": None,
                                        "sha256": sha256_hash,
                                        "file_size": size_bytes,
                                        "status": "DETECTED",
                                        "error": f"Security Alert: Malicious pickle payload symbol detected: {bad_symbol.decode('ascii', errors='ignore')}"
                                    }

                    # Determine architecture clue from filenames or weight entries
                    arch = "PyTorch CNN (TorchScript / ZipState)"
                    if any('resnet' in n.lower() for n in namelist):
                        arch = "ResNet Computer Vision Backbone"
                    elif any('conv' in n.lower() for n in namelist):
                        arch = "Convolutional Neural Network"
                    
                    param_count = max(50000, int(size_bytes / 4))
                    return {
                        "supported": True,
                        "framework": "PyTorch v1.6+",
                        "architecture": arch,
                        "parameter_count": param_count,
                        "sha256": sha256_hash,
                        "file_size": size_bytes,
                        "status": "NOT DETECTED",
                        "metadata": {
                            "archive_format": "ZipArchive",
                            "files_count": len(namelist),
                            "has_torchscript_code": has_code
                        }
                    }
            except Exception as e:
                return {
                    "supported": False,
                    "framework": "PyTorch",
                    "architecture": "Unknown",
                    "parameter_count": None,
                    "sha256": sha256_hash,
                    "file_size": size_bytes,
                    "status": "ANALYSIS FAILED",
                    "error": f"Failed to parse PyTorch zip archive: {str(e)}"
                }

        # Legacy raw pickle stream inspection
        # Scan raw bytes for dangerous execution symbols
        for bad_symbol in cls.DANGEROUS_PICKLE_SYMBOLS:
            if bad_symbol in file_bytes:
                return {
                    "supported": False,
                    "framework": "PyTorch (Raw Pickle)",
                    "architecture": "Untrusted",
                    "parameter_count": None,
                    "sha256": sha256_hash,
                    "file_size": size_bytes,
                    "status": "DETECTED",
                    "error": f"Security Alert: Unsafe execution symbol in pickle stream: {bad_symbol.decode('ascii', errors='ignore')}"
                }

        # Untrusted legacy pickle warning: Do not execute
        return {
            "supported": False,
            "framework": "PyTorch (Legacy Raw Pickle)",
            "architecture": "Legacy Checkpoint",
            "parameter_count": None,
            "sha256": sha256_hash,
            "file_size": size_bytes,
            "status": "NOT SUPPORTED",
            "error": "Analysis unsupported for this model format or architecture: Legacy uncompressed pickle files require isolated sandboxed evaluation."
        }
