# Run this test with: pytest test_aks_authorized_ip_ranges.py (or python -m unittest test_aks_authorized_ip_ranges.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAKSAuthorizedIPRanges(unittest.TestCase):
    def test_aks_authorized_ip_ranges_configured(self):
        aks_file = REPO_ROOT / "terraform/azure/aks.tf"
        self.assertTrue(aks_file.exists(), f"{aks_file} does not exist")

        content = aks_file.read_text()

        # Ensure api_server_authorized_ip_ranges is defined with a non-empty list
        pattern = re.compile(
            r"api_server_authorized_ip_ranges\s*=\s*\[(?P<ips>[^\]]+)\]",
            re.MULTILINE,
        )
        match = pattern.search(content)
        self.assertIsNotNone(
            match,
            "azurerm_kubernetes_cluster must define non-empty api_server_authorized_ip_ranges",
        )
        ips = match.group("ips").strip()
        self.assertTrue(len(ips) > 0, "api_server_authorized_ip_ranges cannot be empty")


if __name__ == "__main__":
    unittest.main()