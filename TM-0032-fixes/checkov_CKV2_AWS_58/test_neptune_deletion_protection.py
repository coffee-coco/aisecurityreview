# Run via: pytest test_neptune_deletion_protection.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestNeptuneClusterDeletionProtection(unittest.TestCase):
    def test_neptune_cluster_has_deletion_protection_enabled(self):
        target_file = REPO_ROOT / "terraform/aws/neptune.tf"
        self.assertTrue(target_file.exists(), f"File not found: {target_file}")

        content = target_file.read_text()

        # Match the aws_neptune_cluster block
        cluster_match = re.search(
            r'resource\s+"aws_neptune_cluster"\s+"default"\s*\{(?P<body>[\s\S]*?)\n\}',
            content,
        )
        self.assertIsNotNone(
            cluster_match,
            "aws_neptune_cluster.default block not found in terraform/aws/neptune.tf",
        )

        body = cluster_match.group("body")
        self.assertRegex(
            body,
            r'deletion_protection\s*=\s*true',
            "aws_neptune_cluster.default must have 'deletion_protection = true' configured",
        )


if __name__ == "__main__":
    unittest.main()