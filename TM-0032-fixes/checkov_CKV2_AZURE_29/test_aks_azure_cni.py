# Run via: pytest test_aks_azure_cni.py (or python -m unittest test_aks_azure_cni.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAKSAzureCNI(unittest.TestCase):
    def test_aks_cluster_has_azure_cni_enabled(self):
        aks_tf_path = REPO_ROOT / "terraform/azure/aks.tf"
        self.assertTrue(aks_tf_path.exists(), f"{aks_tf_path} does not exist")

        content = aks_tf_path.read_text()

        # Locate resource azurerm_kubernetes_cluster "k8s_cluster"
        cluster_match = re.search(
            r'resource\s+"azurerm_kubernetes_cluster"\s+"k8s_cluster"\s*\{([\s\S]*?)^\}',
            content,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            cluster_match,
            "azurerm_kubernetes_cluster.k8s_cluster resource block not found",
        )
        cluster_body = cluster_match.group(1)

        # Locate network_profile block inside azurerm_kubernetes_cluster
        network_profile_match = re.search(
            r'network_profile\s*\{([\s\S]*?)\}',
            cluster_body,
        )
        self.assertIsNotNone(
            network_profile_match,
            "network_profile block missing in azurerm_kubernetes_cluster.k8s_cluster",
        )

        network_profile_body = network_profile_match.group(1)

        # Verify network_plugin is set to "azure"
        plugin_match = re.search(
            r'network_plugin\s*=\s*"azure"',
            network_profile_body,
        )
        self.assertIsNotNone(
            plugin_match,
            'network_profile block must configure network_plugin = "azure"',
        )


if __name__ == "__main__":
    unittest.main()