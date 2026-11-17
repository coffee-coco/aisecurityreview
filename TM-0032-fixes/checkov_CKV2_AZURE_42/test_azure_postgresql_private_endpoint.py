# Run with: pytest test_azure_postgresql_private_endpoint.py (or python -m unittest test_azure_postgresql_private_endpoint.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAzurePostgreSQLPrivateEndpoint(unittest.TestCase):
    def test_postgresql_server_has_private_endpoint(self):
        sql_tf_path = REPO_ROOT / "terraform" / "azure" / "sql.tf"
        self.assertTrue(sql_tf_path.is_file(), f"File not found: {sql_tf_path}")

        content = sql_tf_path.read_text(encoding="utf-8")

        # Verify azurerm_postgresql_server.example exists
        self.assertIn('resource "azurerm_postgresql_server" "example"', content)

        # Verify azurerm_private_endpoint exists and links to azurerm_postgresql_server.example
        endpoint_match = re.search(
            r'resource\s+"azurerm_private_endpoint"\s+"[^"]+"\s*{(.*?)}', content, re.DOTALL
        )
        self.assertIsNotNone(
            endpoint_match,
            "azurerm_private_endpoint resource is missing in sql.tf",
        )

        endpoint_block = endpoint_match.group(1)
        self.assertIn(
            "azurerm_postgresql_server.example.id",
            endpoint_block,
            "azurerm_private_endpoint must reference azurerm_postgresql_server.example.id",
        )
        self.assertIn(
            '"postgresqlServer"',
            endpoint_block,
            "azurerm_private_endpoint must specify subresource_names for postgresqlServer",
        )


if __name__ == "__main__":
    unittest.main()