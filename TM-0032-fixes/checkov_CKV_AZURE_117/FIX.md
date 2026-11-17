### Vulnerability Details
Checkov rule `CKV_AZURE_117` flags Azure Kubernetes Service (AKS) clusters that are not associated with a Customer-Managed Key (CMK) Disk Encryption Set (`disk_encryption_set_id`). By default, AKS node OS disks and attached managed disks are encrypted at rest using platform-managed keys (PMK). Without a Disk Encryption Set referencing customer-managed keys stored in Azure Key Vault, the organization lacks full control over key lifecycle management, rotation, and revocation policies, failing compliance requirements such as NIST SC-28.

### Evidence
In `terraform/azure/aks.tf` at lines 1–35, `resource azurerm_kubernetes_cluster "k8s_cluster"` was defined without the `disk_encryption_set_id` argument.

### Fix
Added `disk_encryption_set_id = azurerm_disk_encryption_set.example.id` to `azurerm_kubernetes_cluster.k8s_cluster`. This associates cluster node disks with a Disk Encryption Set, remediating `CKV_AZURE_117`.

### Verification
The unit test reads `terraform/azure/aks.tf`, parses the `azurerm_kubernetes_cluster` resource block, and asserts that `disk_encryption_set_id` is configured. The test fails on the original code and passes after applying the fix.