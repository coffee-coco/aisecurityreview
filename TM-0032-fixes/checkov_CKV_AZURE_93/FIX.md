### Vulnerability Explanation

Checkov check `CKV_AZURE_93` flags Azure managed disks that do not utilize a Disk Encryption Set (`disk_encryption_set_id`). By default, Azure encrypts managed disks using platform-managed keys (SSE). However, for compliance standards (such as NIST SC-12, SC-13, and SC-28) and strict security requirements, sensitive managed disks must be encrypted using customer-managed keys (CMK) configured via Azure Disk Encryption Sets. In `terraform/azure/storage.tf`, `azurerm_managed_disk.example` not only lacked `disk_encryption_set_id`, but also explicitly disabled legacy disk encryption settings (`encryption_settings { enabled = false }`).

### Remediation

1. Removed the conflicting and insecure `encryption_settings { enabled = false }` block from `azurerm_managed_disk.example`.
2. Added `disk_encryption_set_id = azurerm_disk_encryption_set.example.id` to configure CMK encryption via a Disk Encryption Set.

### Verification

Run the test with `pytest test_azure_managed_disk_encryption_set.py` or run Checkov with `checkov -f terraform/azure/storage.tf --check CKV_AZURE_93`. Checkov will pass and verify that `disk_encryption_set_id` is properly specified.