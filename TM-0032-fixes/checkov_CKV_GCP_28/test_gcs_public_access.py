# Run using: pytest test_gcs_public_access.py (from repository root, or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestGCSBucketPublicAccess(unittest.TestCase):
    def test_gcs_bucket_not_publicly_or_anonymously_accessible(self):
        """
        Test that GCS bucket IAM configurations in gcs.tf do not grant public or
        anonymous access via 'allUsers' or 'allAuthenticatedUsers' (CKV_GCP_28).
        """
        gcs_tf_path = REPO_ROOT / "terraform" / "gcp" / "gcs.tf"
        self.assertTrue(gcs_tf_path.exists(), f"Expected file {gcs_tf_path} to exist.")

        content = gcs_tf_path.read_text()

        # Check for public principals in IAM bindings/members
        self.assertNotRegex(
            content,
            r'"allUsers"',
            "Found 'allUsers' granting public anonymous access in terraform/gcp/gcs.tf",
        )
        self.assertNotRegex(
            content,
            r'"allAuthenticatedUsers"',
            "Found 'allAuthenticatedUsers' granting public access in terraform/gcp/gcs.tf",
        )
        self.assertNotRegex(
            content,
            r'resource\s+"google_storage_bucket_iam_binding"\s+"allow_public_read"',
            "Found 'allow_public_read' IAM binding resource in terraform/gcp/gcs.tf",
        )


if __name__ == "__main__":
    unittest.main()