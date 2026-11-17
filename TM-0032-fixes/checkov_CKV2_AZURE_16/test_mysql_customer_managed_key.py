# Run with: pytest test_mysql_customer_managed_key.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestMySQLCustomerManagedKey(unittest.TestCase):
    def setUp(self):
        self.sql_tf_path = REPO_ROOT / "terraform/azure/sql.tf"
        self.assertTrue(self.sql_tf_path.exists(), f"File not found: {self.sql_tf_path}")
        self.content = self.sql_tf_path.read_text()

    def test_mysql_server_enables_customer_managed_key(self):
        """CKV2_AZURE_16: Ensure azurerm_mysql_server is connected to an azurerm_mysql_server_key resource."""
        self.assertIn(
            'resource "azurerm_mysql_server_key"',
            self.content,
            "azurerm_mysql_server_key resource must be defined to enable CMK encryption.",
        )
        self.assertRegex(
            self.content,
            r'resource\s+"azurerm_mysql_server_key"\s+"[^"]+"\s*\{[^}]*server_id\s*=\s*azurerm_mysql_server\.example\.id',
            "azurerm_mysql_server_key must link to azurerm_mysql_server.example.id via server_id.",
        )
        self.assertRegex(
            self.content,
            r'key_vault_key_id\s*=\s*azurerm_key_vault_key\.example\.id',
            "azurerm_mysql_server_key must specify a Key Vault Key ID.",
        )

    def test_mysql_server_has_identity_block(self):
        """MySQL server requires a managed identity block to access the Key Vault key."""
        self.assertRegex(
            self.content,
            r'identity\s*\{\s*type\s*=\s*"SystemAssigned"\s*\}',
            "azurerm_mysql_server.example must have an identity block with type = 'SystemAssigned'.",
        )


if __name__ == "__main__":
    unittest.main()