# Run via: pytest test_aks_host_encryption.py (from repository root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestAKSHostEncryption(unittest.TestCase):
    def test_aks_cluster_enables_host_encryption(self):
        aks_tf_path = REPO_ROOT / "terraform/azure/aks.tf"
        self.assertTrue(aks_tf_path.is_file(), f"File not found: {aks_tf_path}")

        content = aks_tf_path.read_text()

        # Locate default_node_pool block within azurerm_kubernetes_cluster
        node_pool_match = re.search(
            r'default_node_pool\s*\{([^}]+)\}',
            content,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(node_pool_match, "default_node_pool block not found in aks.tf")

        node_pool_body = node_pool_match.group(1)

        # Check that enable_host_encryption is set to true
        encryption_match = re.search(
            r'enable_host_encryption\s*=\s*true',
            node_pool_body,
        )
        self.assertIsNotNone(
            encryption_match,
            "azurerm_kubernetes_cluster default_node_pool must configure 'enable_host_encryption = true' (CKV_AZURE_227)",
        )


if __name__ == "__main__":
    unittest.main()