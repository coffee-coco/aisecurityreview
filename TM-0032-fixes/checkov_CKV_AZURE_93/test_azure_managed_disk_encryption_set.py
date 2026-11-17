# Run with: pytest test_azure_managed_disk_encryption_set.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestAzureManagedDiskEncryptionSet(unittest.TestCase):
    def setUp(self):
        self.storage_tf_path = REPO_ROOT / "terraform/azure/storage.tf"
        self.assertTrue(self.storage_tf_path.exists(), f"{self.storage_tf_path} does not exist")
        self.content = self.storage_tf_path.read_text()

    def test_managed_disk_uses_disk_encryption_set(self):
        # Extract azurerm_managed_disk.example resource block
        match = re.search(
            r'resource\s+"azurerm_managed_disk"\s+"example"\s*\{(?P<body>[\s\S]*?)\n\}',
            self.content,
        )
        self.assertIsNotNone(match, "azurerm_managed_disk.example resource block not found")
        body = match.group("body")

        # CKV_AZURE_93 requires disk_encryption_set_id to be defined
        self.assertRegex(
            body,
            r'disk_encryption_set_id\s*=',
            "Managed disk 'example' must configure 'disk_encryption_set_id' for customer-managed key encryption",
        )

        # Must not explicitly disable encryption settings
        self.assertNotIn(
            "enabled = false",
            body,
            "Managed disk 'example' should not disable encryption in encryption_settings",
        )

if __name__ == "__main__":
    unittest.main()