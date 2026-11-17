# Run with: pytest test_application_gateway_ssl_policy.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))
TF_FILE = REPO_ROOT / "terraform" / "azure" / "application_gateway.tf"


def extract_resource_block(content: str, resource_type: str, resource_name: str) -> str:
    pattern = rf'resource\s+"{resource_type}"\s+"{resource_name}"\s*\{{'
    match = re.search(pattern, content)
    if not match:
        return ""
    start_idx = match.end() - 1
    depth = 0
    for idx in range(start_idx, len(content)):
        char = content[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return content[start_idx : idx + 1]
    return ""


class TestApplicationGatewaySecureProtocols(unittest.TestCase):
    def test_application_gateway_ssl_policy_configured(self):
        self.assertTrue(TF_FILE.exists(), f"File {TF_FILE} does not exist")
        content = TF_FILE.read_text()

        app_gw_block = extract_resource_block(content, "azurerm_application_gateway", "network")
        self.assertTrue(
            len(app_gw_block) > 0,
            "Resource azurerm_application_gateway.network was not found in application_gateway.tf",
        )

        ssl_match = re.search(r"ssl_policy\s*\{([^}]+)\}", app_gw_block)
        self.assertIsNotNone(
            ssl_match,
            "Resource azurerm_application_gateway.network must define an ssl_policy block",
        )

        min_proto_match = re.search(
            r'min_protocol_version\s*=\s*"(TLSv1_[23])"',
            ssl_match.group(1),
        )
        self.assertIsNotNone(
            min_proto_match,
            "ssl_policy must specify min_protocol_version set to TLSv1_2 or TLSv1_3",
        )


if __name__ == "__main__":
    unittest.main()