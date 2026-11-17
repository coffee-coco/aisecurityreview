# Run with: pytest test_neptune_snapshot_cmk.py (from repository root, or set REPO_ROOT)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestNeptuneClusterSnapshotCMK(unittest.TestCase):
    def test_neptune_cluster_snapshot_encrypted_with_cmk(self):
        neptune_tf = REPO_ROOT / "terraform/aws/neptune.tf"
        self.assertTrue(neptune_tf.exists(), f"File not found: {neptune_tf}")

        content = neptune_tf.read_text()

        # Match aws_neptune_cluster_snapshot blocks
        pattern = re.compile(
            r'resource\s+"aws_neptune_cluster_snapshot"\s+"([^"]+)"\s*\{([^}]+)\}',
            re.DOTALL,
        )
        matches = list(pattern.finditer(content))
        self.assertGreater(
            len(matches),
            0,
            "Expected at least one aws_neptune_cluster_snapshot resource in neptune.tf",
        )

        for match in matches:
            resource_name = match.group(1)
            body = match.group(2)

            # Check that kms_key_id is explicitly configured
            kms_match = re.search(r'kms_key_id\s*=\s*(.+)', body)
            self.assertIsNotNone(
                kms_match,
                f"Resource aws_neptune_cluster_snapshot.{resource_name} is missing 'kms_key_id' (CKV_AWS_280)",
            )

            kms_value = kms_match.group(1).strip().strip('"\'')
            self.assertTrue(
                len(kms_value) > 0,
                f"Resource aws_neptune_cluster_snapshot.{resource_name} has an empty 'kms_key_id'",
            )
            self.assertFalse(
                kms_value.startswith("alias/aws/"),
                f"Resource aws_neptune_cluster_snapshot.{resource_name} must use a customer managed KMS key, not an AWS managed key",
            )


if __name__ == "__main__":
    unittest.main()