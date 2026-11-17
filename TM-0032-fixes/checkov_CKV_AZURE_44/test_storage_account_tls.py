# Run using: pytest test_storage_account_tls.py (from repository root)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_resource_body(content: str, resource_type: str, resource_name: str) -> str:
    pattern = rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{'
    match = re.search(pattern, content)
    if not match:
        return ""
    start = match.end()
    depth = 1
    i = start
    while i < len(content) and depth > 0:
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
        i += 1
    return content[start : i - 1]


class TestStorageAccountTLSVersion(unittest.TestCase):
    def test_mssql_storage_account_min_tls_version(self):
        path = REPO_ROOT / "terraform/azure/mssql.tf"
        self.assertTrue(path.exists(), f"{path} does not exist")
        content = path.read_text(encoding="utf-8")
        body = extract_resource_body(content, "azurerm_storage_account", "security_storage_account")
        self.assertNotEqual(body, "", "Could not find azurerm_storage_account.security_storage_account")
        self.assertRegex(
            body,
            r'min_tls_version\s*=\s*"TLS1_2"',
            "azurerm_storage_account.security_storage_account must configure min_tls_version = \"TLS1_2\"",
        )

    def test_storage_account_min_tls_version(self):
        path = REPO_ROOT / "terraform/azure/storage.tf"
        self.assertTrue(path.exists(), f"{path} does not exist")
        content = path.read_text(encoding="utf-8")
        body = extract_resource_body(content, "azurerm_storage_account", "example")
        self.assertNotEqual(body, "", "Could not find azurerm_storage_account.example")
        self.assertRegex(
            body,
            r'min_tls_version\s*=\s*"TLS1_2"',
            "azurerm_storage_account.example must configure min_tls_version = \"TLS1_2\"",
        )


if __name__ == "__main__":
    unittest.main()