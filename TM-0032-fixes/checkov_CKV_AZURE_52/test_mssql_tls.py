# Run via: pytest test_mssql_tls.py (or python -m unittest test_mssql_tls.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))
MSSQL_FILE = REPO_ROOT / "terraform" / "azure" / "mssql.tf"


class TestMssqlTLSVersion(unittest.TestCase):
    def test_mssql_servers_enforce_minimum_tls_1_2(self):
        self.assertTrue(MSSQL_FILE.is_file(), f"{MSSQL_FILE} does not exist")
        content = MSSQL_FILE.read_text()

        # Match azurerm_mssql_server blocks: resource "azurerm_mssql_server" "<name>" { ... }
        resource_pattern = re.compile(
            r'resource\s+"azurerm_mssql_server"\s+"([^"]+)"\s*\{(.*?)\n\}',
            re.DOTALL,
        )
        servers = resource_pattern.findall(content)
        self.assertGreater(len(servers), 0, "Expected to find azurerm_mssql_server resources")

        for server_name, server_body in servers:
            tls_match = re.search(r'minimum_tls_version\s*=\s*"([^"]+)"', server_body)
            self.assertIsNotNone(
                tls_match,
                f"Resource azurerm_mssql_server.{server_name} missing minimum_tls_version (CKV_AZURE_52)",
            )
            self.assertEqual(
                tls_match.group(1),
                "1.2",
                f"Resource azurerm_mssql_server.{server_name} must have minimum_tls_version set to '1.2'",
            )


if __name__ == "__main__":
    unittest.main()