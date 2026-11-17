# Run with: pytest test_gcs_logging.py (or python -m unittest test_gcs_logging.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestGCSBucketLogging(unittest.TestCase):
    def test_terragoat_website_has_logging_configured(self):
        """Verify that google_storage_bucket.terragoat_website defines access logging (CKV_GCP_62)."""
        gcs_tf = REPO_ROOT / "terraform/gcp/gcs.tf"
        self.assertTrue(gcs_tf.exists(), f"File not found: {gcs_tf}")
        content = gcs_tf.read_text()

        # Match the google_storage_bucket.terragoat_website block
        bucket_match = re.search(
            r'resource\s+"google_storage_bucket"\s+"terragoat_website"\s*{(?P<body>[\s\S]*?)^}',
            content,
            re.MULTILINE
        )
        self.assertIsNotNone(bucket_match, "Resource google_storage_bucket.terragoat_website not found in gcs.tf")

        body = bucket_match.group("body")
        logging_match = re.search(r'logging\s*{[^}]*log_bucket\s*=\s*[^}\s]+[^}]*}', body)
        self.assertIsNotNone(
            logging_match,
            "CKV_GCP_62 violation: google_storage_bucket.terragoat_website is missing logging block with log_bucket"
        )

if __name__ == "__main__":
    unittest.main()