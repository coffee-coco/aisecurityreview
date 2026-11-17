### Vulnerability Description
Checkov rule `CKV_AZURE_59` checks that Azure Storage accounts explicitly disallow public access. In Azure, storage accounts can allow anonymous public read access to containers and blobs unless public access is explicitly disallowed at the account level. When this account-level control is omitted, any container configured with public access will allow unauthenticated external access to blobs, exposing sensitive files or database security audit logs.

### Evidence and Exploitability
In `terraform/azure/mssql.tf` (lines 1-18), the `azurerm_storage_account.security_storage_account` resource is created without `allow_blob_public_access = false`. This storage account receives security alerts and vulnerability scan data from the MSSQL servers configured in the same file (e.g., `alertpolicy1` through `alertpolicy7`).

In `terraform/azure/storage.tf` (lines 23-60), `azurerm_storage_account.example` is also defined without `allow_blob_public_access = false`.

Without this account-level barrier, anonymous internet users could potentially access container data if any container or blob is inadvertently created with public read permissions.

### Remediation
In both `terraform/azure/mssql.tf` and `terraform/azure/storage.tf`, `allow_blob_public_access = false` has been added to the respective `azurerm_storage_account` resource blocks. This enforces at the storage account level that all anonymous public access requests are rejected regardless of container-level settings.

### Verification
Run the test `python3 -m unittest test_storage_disallow_public_access.py` (or `pytest test_storage_disallow_public_access.py`). It parses both Terraform files, verifies that both resources define `allow_blob_public_access = false`, and fails against the original code while passing with the fix applied. You can also run `checkov -c CKV_AZURE_59 -d terraform/azure/` to verify rule satisfaction.