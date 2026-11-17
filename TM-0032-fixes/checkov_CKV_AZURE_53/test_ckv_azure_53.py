# Run using: pytest test_ckv_azure_53.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestMySQLPublicNetworkAccess(unittest.TestCase):
    def test_mysql_server_public_network_access_disabled(self):
        sql_tf_path = REPO_ROOT / "terraform/azure/sql.tf"
        self.assertTrue(sql_tf_path.exists(), f"{sql_tf_path} does not exist")

        content = sql_tf_path.read_text()

        # Extract azurerm_mysql_server block
        match = re.search(r'resource\s+"azurerm_mysql_server"\s+"example"\s*\{(.*?)\n\}', content, re.DOTALL)
        self.assertIsNotNone(match, "azurerm_mysql_server 'example' resource block not found")
        server_block = match.group(1)

        # Find public_network_access_enabled setting
        setting_match = re.search(r'public_network_access_enabled\s*=\s*(\w+)', server_block)
        self.assertIsNotNone(setting_match, "public_network_access_enabled not specified in azurerm_mysql_server.example")
        setting_val = setting_match.group(1).lower()

        self.assertEqual(
            setting_val,
            "false",
            f"Expected public_network_access_enabled to be 'false', but got '{setting_val}'",
        )

if __name__ == "__main__":
    unittest.main()