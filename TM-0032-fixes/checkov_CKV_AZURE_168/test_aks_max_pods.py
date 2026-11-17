# Run with: pytest test_aks_max_pods.py from the repository root (or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAKSMinitmumPodsConfig(unittest.TestCase):
    def test_default_node_pool_min_50_pods(self):
        aks_file = REPO_ROOT / "terraform" / "azure" / "aks.tf"
        self.assertTrue(aks_file.exists(), f"File {aks_file} not found")
        content = aks_file.read_text(encoding="utf-8")

        # Locate default_node_pool block
        match = re.search(r"default_node_pool\s*\{([^}]+)\}", content)
        self.assertIsNotNone(match, "default_node_pool block not found in aks.tf")

        pool_body = match.group(1)
        max_pods_match = re.search(r"max_pods\s*=\s*(\d+)", pool_body)
        self.assertIsNotNone(
            max_pods_match,
            "max_pods is not configured in default_node_pool (CKV_AZURE_168 requires >= 50)",
        )
        max_pods_val = int(max_pods_match.group(1))
        self.assertGreaterEqual(
            max_pods_val,
            50,
            f"max_pods is {max_pods_val}, expected at least 50",
        )


if __name__ == "__main__":
    unittest.main()