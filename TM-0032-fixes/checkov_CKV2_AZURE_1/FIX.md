### Vulnerability Details
Checkov rule `CKV2_AZURE_1` verifies that Azure Storage Accounts containing sensitive or critical data are encrypted with Customer Managed Keys (CMK) rather than relying solely on default Microsoft-managed keys. By default, Azure Storage accounts are encrypted using platform-managed keys; using Customer Managed Keys (stored in Azure Key Vault) provides greater control over key lifecycle, rotation, and revocation, complying with NIST SC-12, SC-13, and SC-28 standards.

In the codebase:
1. `terraform/azure/mssql.tf`: `azurerm_storage_account.security_storage_account` stores MSSQL security alert audit logs, but lacks any CMK configuration or managed identity.
2. `terraform/azure/storage.tf`: `azurerm_storage_account.example` also lacks customer-managed key encryption.

### Remediation
1. Added `identity { type = "SystemAssigned" }` to both `azurerm_storage_account.security_storage_account` and `azurerm_storage_account.example` to allow the storage accounts to authenticate with Azure Key Vault.
2. Created `azurerm_storage_account_customer_managed_key` resources connected to each storage account (`storage_account_id = azurerm_storage_account.<name>.id`) and referencing the module's Key Vault (`azurerm_key_vault.example.id`).

### Verification
Run `pytest test_storage_cmk_encryption.py` or execute Checkov across the Azure Terraform directory (`checkov -d terraform/azure -c CKV2_AZURE_1`) to verify the check passes.