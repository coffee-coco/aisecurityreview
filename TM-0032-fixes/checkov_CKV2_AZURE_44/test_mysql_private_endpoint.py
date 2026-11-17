# Run with: pytest test_mysql_private_endpoint.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestMySQLPrivateEndpoint(unittest.TestCase):
    def test_mysql_server_configured_with_private_endpoint(self):
        sql_tf_path = REPO_ROOT / "terraform/azure/sql.tf"
        self.assertTrue(sql_tf_path.exists(), f"{sql_tf_path} does not exist")
        content = sql_tf_path.read_text()

        # Assert azurerm_mysql_server resource exists
        self.assertIn("azurerm_mysql_server", content)

        # Assert an azurerm_private_endpoint resource connects to azurerm_mysql_server.example.id
        endpoint_pattern = re.compile(
            r'resource\s+"azurerm_private_endpoint"\s+"[^"]+"\s+\{(?P<body>[^}]+(?:\{[^}]*\}[^}]*)*)\}',
            re.MULTILINE,
        )
        matches = endpoint_pattern.findall(content)
        self.assertTrue(
            len(matches) > 0,
            "No azurerm_private_endpoint resource found in terraform/azure/sql.tf",
        )

        endpoint_found = False
        for body in matches:
            if (
                "azurerm_mysql_server.example.id" in body
                and '"mysqlServer"' in body
            ):
                endpoint_found = True
                break

        self.assertTrue(
            endpoint_found,
            "azurerm_private_endpoint connecting to azurerm_mysql_server.example with subresource mysqlServer was not found",
        )


if __name__ == "__main__":
    unittest.main()