# Run: pytest test_azure_mysql_tls.py from the repository root
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestAzureMySQLTLS(unittest.TestCase):
    def test_azurerm_mysql_server_enforces_tls_1_2(self):
        sql_tf = REPO_ROOT / "terraform" / "azure" / "sql.tf"
        self.assertTrue(sql_tf.exists(), f"File not found: {sql_tf}")
        content = sql_tf.read_text()

        # Extract resource "azurerm_mysql_server" "example" block
        match = re.search(
            r'resource\s+"azurerm_mysql_server"\s+"example"\s*{(?P<body>[\s\S]*?)(?:\n}\n|\n}\Z)',
            content
        )
        self.assertIsNotNone(match, "azurerm_mysql_server.example resource block not found")

        body = match.group("body")
        tls_match = re.search(
            r'ssl_minimal_tls_version_enforced\s*=\s*"([^"]+)"',
            body
        )
        self.assertIsNotNone(
            tls_match,
            "azurerm_mysql_server.example is missing ssl_minimal_tls_version_enforced configuration (CKV_AZURE_54)"
        )
        self.assertEqual(
            tls_match.group(1),
            "TLS1_2",
            f"Expected ssl_minimal_tls_version_enforced to be 'TLS1_2', got '{tls_match.group(1)}'"
        )

if __name__ == "__main__":
    unittest.main()