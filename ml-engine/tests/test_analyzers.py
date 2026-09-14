"""
Unit Tests for Python ML Service Analyzers
Tests safe model loader, dataset inspection, and cryptographic provenance verification.
"""

import unittest
import io
import os
import sys
import zipfile
import hashlib

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzers.provenance import ProvenanceEngine
from analyzers.dataset_analyzer import DatasetAnalyzer
from analyzers.risk_engine import RiskEngine
from models.model_loader import SafeModelLoader

class TestProvenanceEngine(unittest.TestCase):
    def test_canonical_record_and_verification(self):
        input_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        model_id = "yolov8-detector"
        model_sha = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        preproc = '{"resize": [640, 640], "norm": [0.485, 0.456, 0.406]}'
        pred = "class_pedestrian"
        conf = 0.945200
        timestamp = "2026-09-12T15:00:00Z"
        nonce = "nonce-abc-123456"

        record_hash, canonical = ProvenanceEngine.generate_record_hash(
            input_image_hash=input_hash,
            model_identifier=model_id,
            model_sha256=model_sha,
            preprocessing_config=preproc,
            prediction=pred,
            confidence=conf,
            timestamp=timestamp,
            nonce=nonce
        )

        self.assertTrue(len(record_hash) == 64)

        # Verification with valid fields
        res_valid = ProvenanceEngine.verify_record(
            expected_hash=record_hash,
            input_image_hash=input_hash,
            model_identifier=model_id,
            model_sha256=model_sha,
            preprocessing_config=preproc,
            prediction=pred,
            confidence=conf,
            timestamp=timestamp,
            nonce=nonce
        )
        self.assertEqual(res_valid["status"], "VERIFIED")
        self.assertTrue(res_valid["is_valid"])

        # Tampered verification: alter confidence
        res_tampered = ProvenanceEngine.verify_record(
            expected_hash=record_hash,
            input_image_hash=input_hash,
            model_identifier=model_id,
            model_sha256=model_sha,
            preprocessing_config=preproc,
            prediction=pred,
            confidence=0.999999, # Tampered!
            timestamp=timestamp,
            nonce=nonce
        )
        self.assertEqual(res_tampered["status"], "TAMPERED")
        self.assertFalse(res_tampered["is_valid"])
        self.assertTrue(len(res_tampered["mismatches"]) > 0)

class TestDatasetAnalyzer(unittest.TestCase):
    def test_empty_corrupt_detection(self):
        res = DatasetAnalyzer.analyze_dataset_bytes("corrupt.zip", b"not-a-zip-file")
        self.assertEqual(res["status"], "ANALYSIS FAILED")
        self.assertEqual(res["corruptedFiles"], 1)

    def test_zip_with_duplicates(self):
        # Create an in-memory zip file with identical sample images
        zip_buffer = io.BytesIO()
        fake_png = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4'
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr("class_a/img1.png", fake_png)
            zf.writestr("class_a/img2.png", fake_png) # Duplicate!
        
        zip_bytes = zip_buffer.getvalue()
        res = DatasetAnalyzer.analyze_dataset_bytes("dataset.zip", zip_bytes)
        self.assertEqual(res["totalSamples"], 2)
        self.assertEqual(len(res["duplicateFiles"]), 1)
        self.assertEqual(res["duplicateFiles"][0]["sampleCount"], 2)

class TestSafeModelLoader(unittest.TestCase):
    def test_unsupported_extension(self):
        res = SafeModelLoader.inspect_model("script.py", b"print('hello')")
        self.assertEqual(res["status"], "NOT SUPPORTED")
        self.assertFalse(res["supported"])

    def test_dangerous_pickle_opcode(self):
        malicious_payload = b"cos\nsystem\n(S'cat /etc/passwd'\ntR."
        res = SafeModelLoader.inspect_model("trojan.pt", malicious_payload)
        self.assertEqual(res["status"], "DETECTED")
        self.assertIn("Security Alert", res["error"])

if __name__ == '__main__':
    unittest.main()
