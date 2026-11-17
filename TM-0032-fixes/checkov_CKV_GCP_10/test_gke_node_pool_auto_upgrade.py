# Run via: pytest test_gke_node_pool_auto_upgrade.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))
GKE_FILE = REPO_ROOT / "terraform/gcp/gke.tf"


class TestGKENodePoolAutoUpgrade(unittest.TestCase):
    def test_custom_node_pool_has_auto_upgrade_enabled(self):
        self.assertTrue(GKE_FILE.exists(), f"File {GKE_FILE} does not exist")
        content = GKE_FILE.read_text(encoding="utf-8")

        node_pool_match = re.search(
            r'resource\s+"google_container_node_pool"\s+"custom_node_pool"\s*\{(?P<body>.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(node_pool_match, "custom_node_pool resource not found in gke.tf")
        body = node_pool_match.group("body")

        management_match = re.search(
            r"management\s*\{(?P<mgmt_body>[^}]+)\}",
            body,
            re.DOTALL,
        )
        self.assertIsNotNone(
            management_match,
            "management block missing in custom_node_pool; automatic node upgrade is not enabled",
        )

        mgmt_body = management_match.group("mgmt_body")
        auto_upgrade_match = re.search(r"auto_upgrade\s*=\s*true\b", mgmt_body)
        self.assertIsNotNone(
            auto_upgrade_match,
            "auto_upgrade must be explicitly set to true in custom_node_pool management block",
        )


if __name__ == "__main__":
    unittest.main()