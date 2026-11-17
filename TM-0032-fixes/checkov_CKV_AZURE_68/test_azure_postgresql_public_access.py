# Run: pytest test_azure_postgresql_public_access.py from repository root
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAzurePostgreSQLPublicNetworkAccess(unittest.TestCase):
    def test_postgresql_server_disables_public_network_access(self):
        target_file = REPO_ROOT / "terraform/azure/sql.tf"
        self.assertTrue(target_file.is_file(), f"File not found: {target_file}")

        content = target_file.read_text()

        # Locate resource "azurerm_postgresql_server" "example" block
        pattern = re.compile(
            r'resource\s+"azurerm_postgresql_server"\s+"example"\s*\{(.*?)\n\}',
            re.DOTALL,
        )
        match = pattern.search(content)
        self.assertIsNotNone(
            match,
            'Could not find resource "azurerm_postgresql_server" "example" block',
        )

        block_body = match.group(1)

        # Assert public_network_access_enabled is explicitly set to false
        prop_match = re.search(
            r'^\s*public_network_access_enabled\s*=\s*(false|true)\b',
            block_body,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            prop_match,
            '"public_network_access_enabled" must be explicitly set on "azurerm_postgresql_server" "example"',
        )
        self.assertEqual(
            prop_match.group(1),
            "false",
            '"public_network_access_enabled" must be set to false',
        )


if __name__ == "__main__":
    unittest.main()