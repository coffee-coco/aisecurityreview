### Vulnerability Details
Checkov check `CKV_AZURE_2` detected that the Azure managed disk `azurerm_managed_disk.example` in `terraform/azure/storage.tf` has encryption explicitly disabled (`enabled = false` within `encryption_settings`). Inactive encryption settings leave virtual machine disks without encryption-at-rest guarantees required by standards such as NIST SC-13, SC-28, and SC-28(1), exposing disk contents to unauthorized access if physical or cloud storage media are compromised.

### Fix
In `terraform/azure/storage.tf`, the `encryption_settings` block for `azurerm_managed_disk.example` was updated from `enabled = false` to `enabled = true`.

### Verification
- Run `pytest test_azure_managed_disk_encryption.py` to confirm that `encryption_settings.enabled` is set to `true` and not `false`.
- Run Checkov (`checkov -f terraform/azure/storage.tf -c CKV_AZURE_2`) to verify that the policy violation is resolved.