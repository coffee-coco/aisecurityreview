# Run with: pytest test_storage_cmk_encryption.py (from REPO_ROOT or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestStorageAccountCustomerManagedKey(unittest.TestCase):
    def _has_cmk_configured(self, content: str, storage_account_name: str) -> bool:
        # Check for dedicated azurerm_storage_account_customer_managed_key linked to this account
        cmk_resource_pattern = rf'resource\s+"azurerm_storage_account_customer_managed_key"\s+"[^"]+"\s*\{{[^}}]*storage_account_id\s*=\s*azurerm_storage_account\.{storage_account_name}\.id[^}}]*\}}'
        # Check for customer_managed_key block inside the storage account
        inline_cmk_pattern = rf'resource\s+"azurerm_storage_account"\s+"{storage_account_name}"\s*\{{(?:(?!^\}}).)*?customer_managed_key\s*\{{'
        return bool(re.search(cmk_resource_pattern, content, re.DOTALL)) or bool(
            re.search(inline_cmk_pattern, content, re.DOTALL | re.MULTILINE)
        )

    def _has_identity_configured(self, content: str, storage_account_name: str) -> bool:
        identity_pattern = rf'resource\s+"azurerm_storage_account"\s+"{storage_account_name}"\s*\{{(?:(?!^\}}).)*?identity\s*\{{(?:(?!^\}}).)*?type\s*=\s*"(SystemAssigned|UserAssigned)"'
        return bool(re.search(identity_pattern, content, re.DOTALL | re.MULTILINE))

    def test_mssql_storage_account_has_cmk(self):
        mssql_path = REPO_ROOT / "terraform/azure/mssql.tf"
        self.assertTrue(mssql_path.exists(), f"{mssql_path} does not exist")
        content = mssql_path.read_text()
        self.assertTrue(
            self._has_cmk_configured(content, "security_storage_account"),
            "azurerm_storage_account.security_storage_account must be encrypted with a Customer Managed Key (CKV2_AZURE_1)",
        )
        self.assertTrue(
            self._has_identity_configured(content, "security_storage_account"),
            "azurerm_storage_account.security_storage_account must configure managed identity for CMK access",
        )

    def test_storage_account_has_cmk(self):
        storage_path = REPO_ROOT / "terraform/azure/storage.tf"
        self.assertTrue(storage_path.exists(), f"{storage_path} does not exist")
        content = storage_path.read_text()
        self.assertTrue(
            self._has_cmk_configured(content, "example"),
            "azurerm_storage_account.example must be encrypted with a Customer Managed Key (CKV2_AZURE_1)",
        )
        self.assertTrue(
            self._has_identity_configured(content, "example"),
            "azurerm_storage_account.example must configure managed identity for CMK access",
        )


if __name__ == "__main__":
    unittest.main()