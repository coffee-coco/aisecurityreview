# Run via: pytest test_gcs_public_access_prevention.py (or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestGCSPublicAccessPrevention(unittest.TestCase):
    def test_terragoat_website_enforces_public_access_prevention(self):
        gcs_tf_path = REPO_ROOT / "terraform" / "gcp" / "gcs.tf"
        self.assertTrue(gcs_tf_path.is_file(), f"File not found: {gcs_tf_path}")

        content = gcs_tf_path.read_text(encoding="utf-8")

        # Extract resource "google_storage_bucket" "terragoat_website" block
        pattern = r'resource\s+"google_storage_bucket"\s+"terragoat_website"\s*\{([^\}]*\{[^\}]*\}[^\}]*|[^\}]*)\}'
        match = re.search(pattern, content, re.DOTALL)
        self.assertIsNotNone(match, "google_storage_bucket.terragoat_website resource block not found")

        bucket_block = match.group(0)
        pap_match = re.search(r'public_access_prevention\s*=\s*"enforced"', bucket_block)
        self.assertIsNotNone(
            pap_match,
            "CKV_GCP_114 violation: 'public_access_prevention = \"enforced\"' is missing from google_storage_bucket.terragoat_website."
        )

if __name__ == "__main__":
    unittest.main()