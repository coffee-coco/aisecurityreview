# Run via: pytest test_aks_upgrade_channel.py (or python -m unittest test_aks_upgrade_channel.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAksUpgradeChannel(unittest.TestCase):
    def test_aks_automatic_channel_upgrade_configured(self):
        aks_file = REPO_ROOT / "terraform/azure/aks.tf"
        self.assertTrue(aks_file.exists(), f"Expected {aks_file} to exist")

        content = aks_file.read_text()

        # Find the azurerm_kubernetes_cluster block
        cluster_match = re.search(
            r'resource\s+"azurerm_kubernetes_cluster"\s+"k8s_cluster"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            cluster_match,
            "Could not find azurerm_kubernetes_cluster.k8s_cluster resource in aks.tf",
        )

        cluster_body = cluster_match.group(1)

        # Search for automatic_channel_upgrade setting with allowed channels
        upgrade_match = re.search(
            r'automatic_channel_upgrade\s*=\s*"([^"]+)"', cluster_body
        )
        self.assertIsNotNone(
            upgrade_match,
            "CKV_AZURE_171: automatic_channel_upgrade is not configured for azurerm_kubernetes_cluster.k8s_cluster",
        )

        valid_channels = {"patch", "rapid", "node-image", "stable"}
        channel_value = upgrade_match.group(1)
        self.assertIn(
            channel_value,
            valid_channels,
            f"automatic_channel_upgrade '{channel_value}' is not one of {valid_channels}",
        )


if __name__ == "__main__":
    unittest.main()