# Run via: pytest test_eks_logging.py (or REPO_ROOT=/path/to/repo pytest test_eks_logging.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestEKSControlPlaneLogging(unittest.TestCase):
    REQUIRED_LOG_TYPES = {"api", "audit", "authenticator", "controllerManager", "scheduler"}

    def test_eks_cluster_has_all_control_plane_log_types_enabled(self):
        tf_file = REPO_ROOT / "terraform/aws/eks.tf"
        self.assertTrue(tf_file.exists(), f"File not found: {tf_file}")

        content = tf_file.read_text()

        # Extract resource aws_eks_cluster "eks_cluster" block
        match = re.search(
            r'resource\s+"aws_eks_cluster"\s+"eks_cluster"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "Resource aws_eks_cluster.eks_cluster not found")
        cluster_block = match.group(1)

        # Search for enabled_cluster_log_types attribute
        log_match = re.search(
            r'enabled_cluster_log_types\s*=\s*\[([^\]]*)\]',
            cluster_block,
        )
        self.assertIsNotNone(
            log_match,
            "CKV_AWS_37 failure: aws_eks_cluster.eks_cluster missing 'enabled_cluster_log_types'",
        )

        log_types_raw = log_match.group(1)
        configured_log_types = set(re.findall(r'"([^"]+)"', log_types_raw))

        missing_log_types = self.REQUIRED_LOG_TYPES - configured_log_types
        self.assertFalse(
            missing_log_types,
            f"CKV_AWS_37 failure: missing required log types: {missing_log_types}",
        )


if __name__ == "__main__":
    unittest.main()