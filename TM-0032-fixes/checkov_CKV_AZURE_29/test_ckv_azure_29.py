# Run: pytest test_ckv_azure_29.py (from repository root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestPostgreSqlSslEnforcement(unittest.TestCase):
    def test_azurerm_postgresql_server_enforces_ssl(self):
        sql_tf_path = REPO_ROOT / "terraform/azure/sql.tf"
        self.assertTrue(sql_tf_path.exists(), f"Expected file {sql_tf_path} to exist")

        content = sql_tf_path.read_text()

        # Extract the azurerm_postgresql_server "example" resource block
        pattern = r'resource\s+"azurerm_postgresql_server"\s+"example"\s*\{(?P<body>[\s\S]*?^\})'
        match = re.search(pattern, content, re.MULTILINE)
        self.assertIsNotNone(match, "azurerm_postgresql_server.example resource block not found")

        body = match.group("body")
        ssl_match = re.search(r'ssl_enforcement_enabled\s*=\s*(true|false)', body)
        self.assertIsNotNone(ssl_match, "ssl_enforcement_enabled attribute not found")
        self.assertEqual(
            ssl_match.group(1),
            "true",
            f"azurerm_postgresql_server.example must have ssl_enforcement_enabled set to true, but found {ssl_match.group(1)}"
        )


if __name__ == "__main__":
    unittest.main()