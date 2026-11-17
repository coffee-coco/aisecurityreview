# Run via: pytest test_tls_version.py (or python -m unittest test_tls_version.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAppServiceTLSVersion(unittest.TestCase):
    def test_app_service1_uses_tls_1_2(self):
        tf_path = REPO_ROOT / "terraform/azure/app_service.tf"
        self.assertTrue(tf_path.exists(), f"Terraform configuration not found at {tf_path}")

        content = tf_path.read_text(encoding="utf-8")

        # Locate resource azurerm_app_service "app-service1"
        pattern = re.compile(
            r'resource\s+"azurerm_app_service"\s+"app-service1"\s*\{(?P<body>[\s\S]*?)\n\}',
            re.MULTILINE,
        )
        match = pattern.search(content)
        self.assertIsNotNone(match, "Resource azurerm_app_service.app-service1 block not found")
        body = match.group("body")

        # Extract min_tls_version within app-service1 site_config
        tls_match = re.search(r'min_tls_version\s*=\s*"([^"]+)"', body)
        self.assertIsNotNone(tls_match, "min_tls_version not specified in app-service1")
        tls_version = tls_match.group(1)

        self.assertEqual(
            tls_version,
            "1.2",
            f"Expected azurerm_app_service.app-service1 min_tls_version to be '1.2', but found '{tls_version}'",
        )


if __name__ == "__main__":
    unittest.main()