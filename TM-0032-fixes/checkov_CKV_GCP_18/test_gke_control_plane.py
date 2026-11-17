# Run with: pytest test_gke_control_plane.py (from repo root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestGKEControlPlaneSecurity(unittest.TestCase):
    def test_gke_control_plane_is_private(self):
        gke_tf_path = REPO_ROOT / "terraform/gcp/gke.tf"
        self.assertTrue(gke_tf_path.exists(), f"File not found: {gke_tf_path}")

        content = gke_tf_path.read_text()

        # Locate the google_container_cluster "workload_cluster" resource block
        cluster_pattern = re.compile(
            r'resource\s+"google_container_cluster"\s+"workload_cluster"\s*\{(?P<body>[\s\S]*?)(?:\n\}\n|\Z)',
            re.MULTILINE,
        )
        match = cluster_pattern.search(content)
        self.assertIsNotNone(
            match,
            'resource "google_container_cluster" "workload_cluster" not found in terraform/gcp/gke.tf',
        )

        cluster_body = match.group("body")

        # Verify private_cluster_config block exists and has enable_private_endpoint set to true (CKV_GCP_18)
        private_config_match = re.search(
            r'private_cluster_config\s*\{(?P<config>[^\}]*)\}',
            cluster_body,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            private_config_match,
            "CKV_GCP_18 violation: GKE cluster is missing 'private_cluster_config' block",
        )

        config_body = private_config_match.group("config")
        self.assertTrue(
            re.search(r'enable_private_endpoint\s*=\s*true', config_body),
            "CKV_GCP_18 violation: 'enable_private_endpoint' must be set to true",
        )


if __name__ == "__main__":
    unittest.main()