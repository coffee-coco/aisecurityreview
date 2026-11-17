# Run via: pytest test_storage_network_rules.py (from repo root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestStorageAccountNetworkRules(unittest.TestCase):
    def test_trusted_microsoft_services_enabled(self):
        target_file = REPO_ROOT / "terraform/azure/storage.tf"
        self.assertTrue(target_file.is_file(), f"File not found: {target_file}")

        content = target_file.read_text()

        pattern = re.compile(
            r'resource\s+"azurerm_storage_account_network_rules"\s+"test"\s*\{(?P<body>[\s\S]*?)\n\}',
            re.MULTILINE,
        )
        match = pattern.search(content)
        self.assertIsNotNone(
            match,
            "Could not find resource 'azurerm_storage_account_network_rules.test' in storage.tf",
        )

        body = match.group("body")
        bypass_match = re.search(r'bypass\s*=\s*\[(?P<bypass_elements>[^\]]*)\]', body)
        self.assertIsNotNone(
            bypass_match,
            "Could not find 'bypass' configuration in network rules",
        )

        bypass_items = [
            item.strip().strip('"').strip("'")
            for item in bypass_match.group("bypass_elements").split(",")
            if item.strip()
        ]

        self.assertIn(
            "AzureServices",
            bypass_items,
            f"'AzureServices' must be included in bypass list to allow trusted Microsoft services, found: {bypass_items}",
        )


if __name__ == "__main__":
    unittest.main()