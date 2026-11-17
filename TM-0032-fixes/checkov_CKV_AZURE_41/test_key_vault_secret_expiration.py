# Run via: pytest test_key_vault_secret_expiration.py (or python -m unittest test_key_vault_secret_expiration.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestKeyVaultSecretExpiration(unittest.TestCase):
    def test_key_vault_secret_has_expiration_date(self):
        kv_file = REPO_ROOT / "terraform/azure/key_vault.tf"
        self.assertTrue(kv_file.exists(), f"{kv_file} does not exist")

        content = kv_file.read_text()
        secret_block_match = re.search(
            r'resource\s+"azurerm_key_vault_secret"\s+"secret"\s+{(?P<body>[^}]+tags\s*=\s*{[^}]*}[^}]*)}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            secret_block_match,
            "Could not find resource 'azurerm_key_vault_secret.secret' block in key_vault.tf",
        )
        secret_body = secret_block_match.group("body")
        expiration_match = re.search(
            r'expiration_date\s*=\s*"[^"]+"',
            secret_body,
        )
        self.assertIsNotNone(
            expiration_match,
            "azurerm_key_vault_secret.secret is missing an expiration_date attribute (violates CKV_AZURE_41)",
        )


if __name__ == "__main__":
    unittest.main()