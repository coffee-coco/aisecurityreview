# Run via: pytest test_bigquery_dataset_access.py (from repo root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestBigQueryDatasetAccess(unittest.TestCase):
    def test_bigquery_dataset_is_not_publicly_accessible(self):
        """
        CKV_GCP_15: Ensure that BigQuery datasets are not anonymously or publicly accessible.
        Verifies google_bigquery_dataset does not grant access to allAuthenticatedUsers or allUsers.
        """
        tf_path = REPO_ROOT / "terraform/gcp/big_data.tf"
        self.assertTrue(tf_path.is_file(), f"{tf_path} does not exist")
        content = tf_path.read_text()

        # Locate the google_bigquery_dataset resource block
        dataset_match = re.search(
            r'resource\s+"google_bigquery_dataset"\s+"[^"]+"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            dataset_match, "Could not find google_bigquery_dataset resource"
        )
        dataset_block = dataset_match.group(1)

        # Check for public/anonymous identifiers in the dataset access configuration
        public_identities = ["allAuthenticatedUsers", "allUsers"]
        for identity in public_identities:
            self.assertNotIn(
                identity,
                dataset_block,
                f"Dataset grants public access via '{identity}', violating CKV_GCP_15",
            )


if __name__ == "__main__":
    unittest.main()