# Run with: pytest test_csek_encryption.py (from repository root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestComputeInstanceBootDiskEncryption(unittest.TestCase):
    def setUp(self):
        self.instance_file = REPO_ROOT / "terraform/gcp/instances.tf"
        self.assertTrue(self.instance_file.exists(), f"Target file not found: {self.instance_file}")
        self.content = self.instance_file.read_text()

    def test_boot_disk_csek_encryption_configured(self):
        """Verify that google_compute_instance.server configures CSEK for its boot_disk."""
        # Locate google_compute_instance "server" resource block
        instance_match = re.search(
            r'resource\s+"google_compute_instance"\s+"server"\s*\{(?P<body>[\s\S]*?)(?:\n\}\n|\Z)',
            self.content,
        )
        self.assertIsNotNone(instance_match, "google_compute_instance 'server' resource not found")
        instance_body = instance_match.group("body")

        # Locate boot_disk block within google_compute_instance.server
        boot_disk_match = re.search(r'boot_disk\s*\{(?P<body>[\s\S]*?)\n\s*\}', instance_body)
        self.assertIsNotNone(boot_disk_match, "boot_disk block not found in google_compute_instance 'server'")
        boot_disk_body = boot_disk_match.group("body")

        # Check for disk_encryption_key_raw
        csek_match = re.search(r'disk_encryption_key_raw\s*=\s*"[^"]+"', boot_disk_body)
        self.assertIsNotNone(
            csek_match,
            "boot_disk is missing disk_encryption_key_raw (CKV_GCP_38: CSEK encryption required)",
        )


if __name__ == "__main__":
    unittest.main()