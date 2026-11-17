# Run with: pytest <file> from the root of the reviewed repository, or with REPO_ROOT set.
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_block(text: str, header: str):
    idx = text.find(header)
    if idx == -1:
        return None
    start = text.find("{", idx)
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
    return None


class TestAzureManagedDiskEncryption(unittest.TestCase):
    def test_managed_disk_encryption_is_enabled(self):
        target_file = REPO_ROOT / "terraform" / "azure" / "storage.tf"
        self.assertTrue(target_file.exists(), f"Expected file {target_file} does not exist")

        content = target_file.read_text(encoding="utf-8")
        disk_block = extract_block(content, 'resource "azurerm_managed_disk" "example"')
        self.assertIsNotNone(disk_block, 'Resource azurerm_managed_disk "example" was not found')

        enc_block = extract_block(disk_block, "encryption_settings")
        self.assertIsNotNone(enc_block, "encryption_settings block was not found in azurerm_managed_disk.example")

        self.assertRegex(
            enc_block,
            r"enabled\s*=\s*true",
            "azurerm_managed_disk.example encryption_settings must have enabled = true"
        )
        self.assertNotRegex(
            enc_block,
            r"enabled\s*=\s*false",
            "azurerm_managed_disk.example encryption_settings must not have enabled = false"
        )


if __name__ == "__main__":
    unittest.main()