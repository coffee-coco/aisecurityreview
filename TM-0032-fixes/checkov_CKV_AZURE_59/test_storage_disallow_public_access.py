# Run with: python3 -m unittest test_storage_disallow_public_access.py
# or with REPO_ROOT set: pytest test_storage_disallow_public_access.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_resource_body(content: str, resource_type: str, resource_name: str) -> str:
    """Extract the body of a Terraform resource block with brace balancing."""
    pattern = rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{'
    match = re.search(pattern, content)
    if not match:
        return ""
    start_idx = match.end() - 1
    depth = 0
    body_chars = []
    for i in range(start_idx, len(content)):
        char = content[i]
        if char == "{":
            depth += 1
            if depth > 1:
                body_chars.append(char)
        elif char == "}":
            depth -= 1
            if depth == 0:
                break
            body_chars.append(char)
        else:
            if depth >= 1:
                body_chars.append(char)
    return "".join(body_chars)


class TestStorageAccountDisallowPublicAccess(unittest.TestCase):
    def test_security_storage_account_disallows_public_access(self):
        mssql_file = REPO_ROOT / "terraform/azure/mssql.tf"
        self.assertTrue(mssql_file.exists(), f"{mssql_file} does not exist")
        content = mssql_file.read_text()
        body = extract_resource_body(content, "azurerm_storage_account", "security_storage_account")
        self.assertTrue(body, "Resource 'azurerm_storage_account.security_storage_account' not found")
        match = re.search(
            r'^\s*(allow_blob_public_access|allow_nested_items_to_be_public)\s*=\s*false\b',
            body,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            match,
            "azurerm_storage_account.security_storage_account must disallow public access by setting "
            "allow_blob_public_access = false (CKV_AZURE_59)",
        )

    def test_example_storage_account_disallows_public_access(self):
        storage_file = REPO_ROOT / "terraform/azure/storage.tf"
        self.assertTrue(storage_file.exists(), f"{storage_file} does not exist")
        content = storage_file.read_text()
        body = extract_resource_body(content, "azurerm_storage_account", "example")
        self.assertTrue(body, "Resource 'azurerm_storage_account.example' not found")
        match = re.search(
            r'^\s*(allow_blob_public_access|allow_nested_items_to_be_public)\s*=\s*false\b',
            body,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            match,
            "azurerm_storage_account.example must disallow public access by setting "
            "allow_blob_public_access = false (CKV_AZURE_59)",
        )


if __name__ == "__main__":
    unittest.main()