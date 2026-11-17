# Run via: pytest test_mssql_public_network_access.py (or python -m unittest test_mssql_public_network_access.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestMSSQLPublicNetworkAccess(unittest.TestCase):
    def test_mssql_servers_disable_public_network_access(self):
        mssql_file = REPO_ROOT / "terraform/azure/mssql.tf"
        self.assertTrue(mssql_file.exists(), f"File not found: {mssql_file}")

        content = mssql_file.read_text()

        # Extract all azurerm_mssql_server blocks
        pattern = re.compile(r'resource\s+"azurerm_mssql_server"\s+"([^"]+)"\s*\{(.*?)\n\}', re.DOTALL)
        matches = pattern.findall(content)

        self.assertGreater(len(matches), 0, "No azurerm_mssql_server resources found")

        failing_servers = []
        for server_name, block_content in matches:
            # Check for public_network_access_enabled = false
            if not re.search(r'public_network_access_enabled\s*=\s*false', block_content):
                failing_servers.append(server_name)

        self.assertEqual(
            [],
            failing_servers,
            f"The following azurerm_mssql_server resources do not have public network access disabled: {failing_servers}"
        )


if __name__ == "__main__":
    unittest.main()