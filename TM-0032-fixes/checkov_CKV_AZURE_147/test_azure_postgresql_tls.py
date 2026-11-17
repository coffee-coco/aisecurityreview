# Run: pytest test_azure_postgresql_tls.py from the repository root (or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestPostgreSQLTLSConfig(unittest.TestCase):
    def test_azurerm_postgresql_server_latest_tls(self):
        sql_tf_path = REPO_ROOT / "terraform/azure/sql.tf"
        self.assertTrue(sql_tf_path.exists(), f"{sql_tf_path} does not exist")
        content = sql_tf_path.read_text(encoding="utf-8")

        # Locate azurerm_postgresql_server.example block
        match = re.search(
            r'resource\s+"azurerm_postgresql_server"\s+"example"\s*\{(.*?)(?=\nresource|\Z)',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            match, "azurerm_postgresql_server.example resource block not found"
        )
        block = match.group(1)

        tls_match = re.search(
            r'ssl_minimal_tls_version_enforced\s*=\s*"([^"]+)"',
            block,
        )
        self.assertIsNotNone(
            tls_match,
            "azurerm_postgresql_server.example is missing ssl_minimal_tls_version_enforced",
        )
        self.assertEqual(
            tls_match.group(1),
            "TLS1_2",
            f"Expected ssl_minimal_tls_version_enforced to be 'TLS1_2', got '{tls_match.group(1)}'",
        )


if __name__ == "__main__":
    unittest.main()