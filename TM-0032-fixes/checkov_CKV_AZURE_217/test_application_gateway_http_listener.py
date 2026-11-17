# Run with: pytest test_application_gateway_http_listener.py (or python -m unittest test_application_gateway_http_listener.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestApplicationGatewayHTTPListener(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform/azure/application_gateway.tf"
        self.assertTrue(self.tf_file.exists(), f"Target file does not exist: {self.tf_file}")

    def test_http_listener_disallows_insecure_http(self):
        """Assert that azurerm_application_gateway http_listener enforces HTTPS (CKV_AZURE_217)."""
        content = self.tf_file.read_text(encoding="utf-8")

        listener_blocks = re.findall(r"http_listener\s*\{([^}]+)\}", content, re.MULTILINE)
        self.assertTrue(listener_blocks, "No http_listener block found in azurerm_application_gateway")

        for block in listener_blocks:
            protocol_match = re.search(r"protocol\s*=\s*["']([^"']+)["']", block)
            self.assertIsNotNone(protocol_match, "http_listener must define a protocol")
            protocol = protocol_match.group(1)

            self.assertNotEqual(
                protocol.lower(),
                "http",
                f"CKV_AZURE_217 failed: http_listener configured with insecure protocol '{protocol}'."
            )
            self.assertEqual(
                protocol.lower(),
                "https",
                f"Expected http_listener protocol to be 'Https', found '{protocol}'."
            )


if __name__ == "__main__":
    unittest.main()