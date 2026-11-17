### Vulnerability Details
Checkov rule `CKV_AZURE_44` requires Azure Storage Accounts to enforce TLS 1.2 as the minimum TLS version (`min_tls_version = "TLS1_2"`). When `min_tls_version` is omitted in `azurerm_storage_account` resource definitions, the storage account may default to permitting outdated cryptographic protocols (such as TLS 1.0 and TLS 1.1). These deprecated TLS versions contain known cryptographic flaws and vulnerabilities (e.g., POODLE, BEAST) that leave data in transit susceptible to interception or downgrade attacks.

### Why Exploitable
Both storage accounts:
1. `azurerm_storage_account.security_storage_account` in `terraform/azure/mssql.tf` (lines 1-18)
2. `azurerm_storage_account.example` in `terraform/azure/storage.tf` (lines 23-60)

did not specify `min_tls_version`. Consequently, clients negotiating connections over TLS 1.0 or 1.1 could communicate with these storage endpoints without restriction.

### Fix Details
Explicitly added `min_tls_version = "TLS1_2"` to both `azurerm_storage_account` resource definitions in `terraform/azure/mssql.tf` and `terraform/azure/storage.tf`.

### Verification
- Run `pytest test_storage_account_tls.py` to assert that both storage account configurations explicitly set `min_tls_version = "TLS1_2"`.
- Run Checkov (`checkov -c CKV_AZURE_44 -d terraform/azure`) to ensure compliance with the policy.