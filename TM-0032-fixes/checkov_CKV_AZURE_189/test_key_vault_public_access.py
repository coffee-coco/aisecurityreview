# Run via: pytest test_key_vault_public_access.py (from repository root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestKeyVaultPublicAccess(unittest.TestCase):
    def test_key_vault_disables_public_network_access(self):
        kv_file = REPO_ROOT / "terraform/azure/key_vault.tf"
        self.assertTrue(kv_file.exists(), f"File not found: {kv_file}")

        content = kv_file.read_text()

        # Extract azurerm_key_vault.example block
        block_match = re.search(
            r'resource\s+"azurerm_key_vault"\s+"example"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            block_match, "azurerm_key_vault.example resource block not found"
        )
        block_body = block_match.group(1)

        # Checkov CKV_AZURE_189 requires public_network_access_enabled = false
        setting_match = re.search(
            r'public_network_access_enabled\s*=\s*false',
            block_body,
        )
        self.assertIsNotNone(
            setting_match,
            "azurerm_key_vault.example does not have public_network_access_enabled set to false (CKV_AZURE_189)",
        )


if __name__ == "__main__":
    unittest.main()