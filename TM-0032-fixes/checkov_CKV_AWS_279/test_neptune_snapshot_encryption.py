# pytest test_neptune_snapshot_encryption.py from the repository root (or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestNeptuneSnapshotEncryption(unittest.TestCase):
    def test_neptune_cluster_snapshot_storage_encrypted(self):
        target_file = REPO_ROOT / "terraform/aws/neptune.tf"
        self.assertTrue(target_file.exists(), f"Expected file {target_file} to exist")

        content = target_file.read_text(encoding="utf-8")

        # Locate the aws_neptune_cluster_snapshot.default resource block
        pattern = re.compile(
            r'resource\s+"aws_neptune_cluster_snapshot"\s+"default"\s*\{([^}]*)\}',
            re.MULTILINE,
        )
        match = pattern.search(content)
        self.assertIsNotNone(
            match,
            "Could not find aws_neptune_cluster_snapshot.default resource block",
        )

        snapshot_block = match.group(1)
        self.assertRegex(
            snapshot_block,
            r"storage_encrypted\s*=\s*true",
            "aws_neptune_cluster_snapshot.default must have 'storage_encrypted = true' to comply with CKV_AWS_279",
        )


if __name__ == "__main__":
    unittest.main()