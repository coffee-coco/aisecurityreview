# Run with: pytest test_gke_intranode_visibility.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestGKEIntranodeVisibility(unittest.TestCase):
    def test_workload_cluster_intranode_visibility_enabled(self):
        cluster_file = REPO_ROOT / "terraform/gcp/gke.tf"
        self.assertTrue(cluster_file.exists(), f"{cluster_file} does not exist")

        content = cluster_file.read_text()

        # Locate resource "google_container_cluster" "workload_cluster" block
        match = re.search(
            r'resource\s+"google_container_cluster"\s+"workload_cluster"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            match,
            "google_container_cluster.workload_cluster resource block not found in gke.tf",
        )

        cluster_block = match.group(1)

        # Check that enable_intranode_visibility is set to true (CKV_GCP_61)
        visibility_match = re.search(
            r'enable_intranode_visibility\s*=\s*true\b',
            cluster_block,
        )
        self.assertIsNotNone(
            visibility_match,
            "google_container_cluster.workload_cluster must have enable_intranode_visibility set to true (CKV_GCP_61)",
        )


if __name__ == "__main__":
    unittest.main()