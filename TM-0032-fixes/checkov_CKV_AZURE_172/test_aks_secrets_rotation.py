# Run with: pytest test_aks_secrets_rotation.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAKSSecretsRotation(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform/azure/aks.tf"
        self.assertTrue(self.tf_file.exists(), f"Target file {self.tf_file} does not exist")
        self.content = self.tf_file.read_text()

    def test_key_vault_secrets_provider_rotation_enabled(self):
        """
        CKV_AZURE_172 requires azurerm_kubernetes_cluster to have
        key_vault_secrets_provider with secret_rotation_enabled set to true.
        """
        # Locate azurerm_kubernetes_cluster resource
        cluster_match = re.search(
            r'resource\s+"azurerm_kubernetes_cluster"\s+"k8s_cluster"\s*\{(.*?)\n\}',
            self.content,
            re.DOTALL,
        )
        self.assertIsNotNone(cluster_match, "azurerm_kubernetes_cluster resource not found")
        cluster_body = cluster_match.group(1)

        # Locate key_vault_secrets_provider block
        kv_provider_match = re.search(
            r'key_vault_secrets_provider\s*\{(.*?)\}',
            cluster_body,
            re.DOTALL,
        )
        self.assertIsNotNone(
            kv_provider_match,
            "key_vault_secrets_provider block is missing in azurerm_kubernetes_cluster",
        )
        kv_body = kv_provider_match.group(1)

        # Verify secret_rotation_enabled is set to true
        rotation_match = re.search(
            r'secret_rotation_enabled\s*=\s*true',
            kv_body,
        )
        self.assertIsNotNone(
            rotation_match,
            "key_vault_secrets_provider.secret_rotation_enabled must be set to true",
        )


if __name__ == "__main__":
    unittest.main()