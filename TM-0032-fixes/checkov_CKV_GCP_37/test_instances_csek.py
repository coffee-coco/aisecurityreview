# Run with: pytest test_instances_csek.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestDiskCSEKEncryption(unittest.TestCase):
    def test_unencrypted_disk_has_csek(self):
        instances_tf_path = REPO_ROOT / "terraform/gcp/instances.tf"
        self.assertTrue(
            instances_tf_path.is_file(),
            f"File not found: {instances_tf_path}",
        )

        content = instances_tf_path.read_text()

        # Locate resource "google_compute_disk" "unencrypted_disk"
        disk_pattern = re.compile(
            r'resource\s+"google_compute_disk"\s+"unencrypted_disk"\s*\{(.*?)\n\}',
            re.DOTALL,
        )
        match = disk_pattern.search(content)
        self.assertIsNotNone(
            match,
            'Resource "google_compute_disk" "unencrypted_disk" not found',
        )

        disk_block = match.group(1)

        # Verify disk_encryption_key block is present with raw_key
        csek_pattern = re.compile(
            r'disk_encryption_key\s*\{[^}]*raw_key\s*=',
            re.DOTALL,
        )
        self.assertTrue(
            csek_pattern.search(disk_block),
            "google_compute_disk.unencrypted_disk missing disk_encryption_key with raw_key (CSEK)",
        )


if __name__ == "__main__":
    unittest.main()