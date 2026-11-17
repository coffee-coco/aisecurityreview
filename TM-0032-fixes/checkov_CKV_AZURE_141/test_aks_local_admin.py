# Run with: pytest test_aks_local_admin.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAKSLocalAdmin(unittest.TestCase):
    def test_local_account_disabled(self):
        tf_file = REPO_ROOT / "terraform/azure/aks.tf"
        self.assertTrue(tf_file.exists(), f"File {tf_file} does not exist")
        content = tf_file.read_text()

        cluster_block_match = re.search(
            r'resource\s+"?azurerm_kubernetes_cluster"?\s+"k8s_cluster"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            cluster_block_match,
            "azurerm_kubernetes_cluster k8s_cluster resource block not found",
        )
        block_content = cluster_block_match.group(1)

        match = re.search(
            r'^\s*local_account_disabled\s*=\s*true\b',
            block_content,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            match,
            "azurerm_kubernetes_cluster.k8s_cluster must have 'local_account_disabled = true' to remediate CKV_AZURE_141",
        )


if __name__ == "__main__":
    unittest.main()