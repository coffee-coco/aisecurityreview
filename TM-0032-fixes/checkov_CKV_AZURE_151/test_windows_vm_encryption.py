# Run with: pytest test_windows_vm_encryption.py from the repository root (or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestWindowsVMEncryption(unittest.TestCase):
    def test_windows_vm_encryption_at_host_enabled(self):
        instance_tf_path = REPO_ROOT / "terraform/azure/instance.tf"
        self.assertTrue(instance_tf_path.exists(), f"Missing {instance_tf_path}")

        content = instance_tf_path.read_text()

        # Locate azurerm_windows_virtual_machine block
        match = re.search(
            r'resource\s+"?azurerm_windows_virtual_machine"?\s+"windows_machine"\s*\{(?P<body>[\s\S]*?)(?:\n\}\s*$|\n\}\n)',
            content,
        )
        self.assertIsNotNone(match, "azurerm_windows_virtual_machine.windows_machine not found")
        body = match.group("body")

        # Checkov CKV_AZURE_151 requires encryption_at_host_enabled = true
        encryption_match = re.search(r'encryption_at_host_enabled\s*=\s*true', body, re.IGNORECASE)
        self.assertIsNotNone(
            encryption_match,
            "azurerm_windows_virtual_machine.windows_machine must have encryption_at_host_enabled set to true",
        )


if __name__ == "__main__":
    unittest.main()