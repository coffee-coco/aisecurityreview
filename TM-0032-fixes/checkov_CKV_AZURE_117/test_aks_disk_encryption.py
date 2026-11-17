# Run with: pytest test_aks_disk_encryption.py (or python -m unittest test_aks_disk_encryption.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAKSDiskEncryptionSet(unittest.TestCase):
    def test_aks_uses_disk_encryption_set(self):
        aks_tf_path = REPO_ROOT / "terraform/azure/aks.tf"
        self.assertTrue(aks_tf_path.is_file(), f"File not found: {aks_tf_path}")

        content = aks_tf_path.read_text()

        # Locate resource azurerm_kubernetes_cluster block
        match = re.search(
            r'resource\s+"azurerm_kubernetes_cluster"\s+"([^"]+)"\s*{(?P<body>[\s\S]*?)^}',
            content,
            re.MULTILINE,
        )
        self.assertIsNotNone(match, "azurerm_kubernetes_cluster resource not found in aks.tf")

        cluster_body = match.group("body")

        # Verify disk_encryption_set_id is defined with a valid non-empty value
        des_match = re.search(
            r'^\s*disk_encryption_set_id\s*=\s*(\S+)', cluster_body, re.MULTILINE
        )
        self.assertIsNotNone(
            des_match,
            "azurerm_kubernetes_cluster is missing 'disk_encryption_set_id' (violates CKV_AZURE_117)",
        )
        self.assertTrue(
            des_match.group(1).strip() not in ('""', "''", "null"),
            "disk_encryption_set_id must not be empty or null",
        )


if __name__ == "__main__":
    unittest.main()