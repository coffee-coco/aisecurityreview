# Run via: pytest test_neptune_storage_encryption.py (from repo root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestNeptuneStorageEncryption(unittest.TestCase):
    def test_neptune_cluster_storage_encrypted(self):
        neptune_tf_path = REPO_ROOT / "terraform/aws/neptune.tf"
        self.assertTrue(neptune_tf_path.is_file(), f"{neptune_tf_path} does not exist")

        content = neptune_tf_path.read_text()

        # Extract resource "aws_neptune_cluster" block
        cluster_match = re.search(
            r'resource\s+"aws_neptune_cluster"\s+"[^"]+"\s*\{(?P<body>[^\}]*)\}',
            content,
            re.DOTALL
        )
        self.assertIsNotNone(cluster_match, "aws_neptune_cluster resource block not found")
        cluster_body = cluster_match.group("body")

        storage_encrypted_match = re.search(
            r'storage_encrypted\s*=\s*(?P<val>true|false)',
            cluster_body
        )
        self.assertIsNotNone(
            storage_encrypted_match,
            "storage_encrypted attribute missing in aws_neptune_cluster"
        )
        self.assertEqual(
            storage_encrypted_match.group("val"),
            "true",
            f"Neptune cluster storage_encrypted must be set to true, found: {storage_encrypted_match.group('val')}"
        )

if __name__ == "__main__":
    unittest.main()