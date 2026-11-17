# Run via: pytest test_managed_disk_public_access.py (or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestManagedDiskPublicAccess(unittest.TestCase):
    def test_managed_disk_disables_public_network_access(self):
        storage_tf_path = REPO_ROOT / "terraform/azure/storage.tf"
        self.assertTrue(storage_tf_path.exists(), f"Target file not found: {storage_tf_path}")

        content = storage_tf_path.read_text()

        # Extract azurerm_managed_disk "example" block
        match = re.search(
            r'resource\s+"azurerm_managed_disk"\s+"example"\s*\{(?P<body>[\s\S]*?)\n\}\n', 
            content
        )
        self.assertIsNotNone(match, "azurerm_managed_disk.example resource block not found")
        body = match.group("body")

        # Verify public_network_access_enabled is set to false
        pna_match = re.search(r'public_network_access_enabled\s*=\s*(false|true)', body)
        self.assertIsNotNone(
            pna_match, 
            "azurerm_managed_disk.example must explicitly configure 'public_network_access_enabled'"
        )
        self.assertEqual(
            pna_match.group(1),
            "false",
            f"Expected public_network_access_enabled to be 'false', but got '{pna_match.group(1)}'"
        )

if __name__ == "__main__":
    unittest.main()