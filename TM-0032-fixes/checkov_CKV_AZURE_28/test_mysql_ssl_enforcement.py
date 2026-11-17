# Run via: pytest test_mysql_ssl_enforcement.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestMySqlSslEnforcement(unittest.TestCase):
    def test_azurerm_mysql_server_enforces_ssl(self):
        target_file = REPO_ROOT / "terraform/azure/sql.tf"
        self.assertTrue(target_file.exists(), f"{target_file} does not exist")

        content = target_file.read_text()

        # Locate azurerm_mysql_server resource block
        resource_match = re.search(
            r'resource\s+"azurerm_mysql_server"\s+"example"\s*\{(?P<body>[\s\S]*?)\n\}',
            content,
        )
        self.assertIsNotNone(resource_match, "azurerm_mysql_server.example resource block not found")
        block_body = resource_match.group("body")

        ssl_match = re.search(r'ssl_enforcement_enabled\s*=\s*(true|false)', block_body)
        self.assertIsNotNone(
            ssl_match,
            "ssl_enforcement_enabled configuration not found in azurerm_mysql_server.example",
        )

        self.assertEqual(
            ssl_match.group(1),
            "true",
            f"azurerm_mysql_server.example has ssl_enforcement_enabled = {ssl_match.group(1)}; expected true (CKV_AZURE_28)",
        )


if __name__ == "__main__":
    unittest.main()