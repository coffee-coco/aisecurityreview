# Run via: pytest test_key_vault_secret_content_type.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestKeyVaultSecretContentType(unittest.TestCase):
    def test_key_vault_secret_has_content_type(self):
        kv_file = REPO_ROOT / "terraform/azure/key_vault.tf"
        self.assertTrue(kv_file.is_file(), f"File not found: {kv_file}")

        content = kv_file.read_text()

        # Find the azurerm_key_vault_secret resource block
        pattern = r'resource\s+"azurerm_key_vault_secret"\s+"secret"\s+\{(.*?)\n\}'
        match = re.search(pattern, content, re.DOTALL)
        self.assertIsNotNone(match, "azurerm_key_vault_secret.secret block not found")

        block_body = match.group(1)
        content_type_match = re.search(r'content_type\s*=\s*"([^"]+)"', block_body)
        self.assertIsNotNone(
            content_type_match,
            "azurerm_key_vault_secret.secret must have 'content_type' defined",
        )
        self.assertTrue(
            len(content_type_match.group(1).strip()) > 0,
            "content_type must not be empty",
        )


if __name__ == "__main__":
    unittest.main()