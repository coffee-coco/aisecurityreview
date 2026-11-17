### Vulnerability Analysis
Checkov rule `CKV2_AZURE_16` requires Azure MySQL servers to enable Customer-Managed Keys (CMK) for data encryption at rest (NIST SC-12, SC-13, SC-28). Without customer-managed key encryption, the server defaults to service-managed keys, preventing organizations from controlling key lifecycles, access policies, rotation, and revocation.

In `terraform/azure/sql.tf` (lines 44–71), `azurerm_mysql_server.example` was defined without an associated `azurerm_mysql_server_key` resource and lacked an `identity` block required to authenticate to Azure Key Vault.

### Fix Details
1. Added a system-assigned managed identity block (`identity { type = "SystemAssigned" }`) to `azurerm_mysql_server.example`. This provides the Azure Active Directory principal needed by the MySQL server to access Key Vault keys.
2. Added the `azurerm_mysql_server_key` resource linking `server_id = azurerm_mysql_server.example.id` to `key_vault_key_id = azurerm_key_vault_key.example.id`.

### Verification
Run the test via `pytest test_mysql_customer_managed_key.py`. Alternatively, run Checkov: `checkov -f terraform/azure/sql.tf -c CKV2_AZURE_16`.