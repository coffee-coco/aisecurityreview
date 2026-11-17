# Run via: pytest test_azure_sql_ad_admin.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAzureSqlADAdminConfigured(unittest.TestCase):
    def test_azurerm_sql_server_has_ad_admin(self):
        sql_tf_path = REPO_ROOT / "terraform/azure/sql.tf"
        self.assertTrue(sql_tf_path.exists(), f"{sql_tf_path} does not exist")
        content = sql_tf_path.read_text()

        # Verify azurerm_sql_server exists
        self.assertIn('resource "azurerm_sql_server" "example"', content)

        # Checkov CKV2_AZURE_7 checks that azurerm_sql_server has an associated
        # azurerm_sql_active_directory_administrator resource.
        ad_admin_pattern = re.compile(
            r'resource\s+"azurerm_sql_active_directory_administrator"\s+"(\w+)"\s*\{' r"([\s\S]*?)" r"\}",
            re.MULTILINE,
        )
        matches = ad_admin_pattern.findall(content)
        self.assertTrue(
            len(matches) > 0,
            "azurerm_sql_server is missing an azurerm_sql_active_directory_administrator resource (CKV2_AZURE_7)",
        )

        # Verify the administrator is linked to azurerm_sql_server.example.name
        server_name_pattern = re.compile(r"server_name\s*=\s*azurerm_sql_server\.example\.name")
        linked = any(server_name_pattern.search(body) for _, body in matches)
        self.assertTrue(
            linked,
            "azurerm_sql_active_directory_administrator is not linked to azurerm_sql_server.example.name",
        )


if __name__ == "__main__":
    unittest.main()