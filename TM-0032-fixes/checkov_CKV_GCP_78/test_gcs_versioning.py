# Run via: pytest test_gcs_versioning.py (or python -m unittest test_gcs_versioning.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestGCSBucketVersioning(unittest.TestCase):
    def test_terragoat_website_has_versioning_enabled(self):
        gcs_file_path = REPO_ROOT / "terraform/gcp/gcs.tf"
        self.assertTrue(gcs_file_path.is_file(), f"File not found: {gcs_file_path}")

        content = gcs_file_path.read_text()

        # Locate resource "google_storage_bucket" "terragoat_website" block
        pattern = re.compile(
            r'resource\s+"google_storage_bucket"\s+"terragoat_website"\s*\{(.*?)\n\}',
            re.DOTALL,
        )
        match = pattern.search(content)
        self.assertIsNotNone(
            match,
            "Could not find resource 'google_storage_bucket' 'terragoat_website' in terraform/gcp/gcs.tf",
        )

        bucket_body = match.group(1)

        # Check that versioning block exists and is enabled
        versioning_pattern = re.compile(
            r'versioning\s*\{[^}]*enabled\s*=\s*true[^}]*\}',
            re.MULTILINE,
        )
        self.assertIsNotNone(
            versioning_pattern.search(bucket_body),
            "google_storage_bucket.terragoat_website does not have versioning { enabled = true } configured",
        )


if __name__ == "__main__":
    unittest.main()