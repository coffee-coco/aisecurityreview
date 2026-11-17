### Vulnerability Description
Checkov check `CKV_AZURE_227` flags Azure Kubernetes Service (AKS) clusters where encryption at host is not enabled. Without host encryption, data stored on the VM host caching, temporary scratch disks, and ephemeral storage used by Kubernetes worker nodes are stored without end-to-end host-level encryption. In addition, data flows between the AKS compute VMs and Azure Storage are not encrypted at the host level.

### Evidence
In `terraform/azure/aks.tf` (lines 9–13), the `default_node_pool` block was defined as:
```hcl
default_node_pool {
  name       = "default"
  vm_size    = "Standard_D2_v2"
  node_count = 2
}
```
Because `enable_host_encryption` was omitted, it defaulted to `false`.

### Remediation
In `terraform/azure/aks.tf`, `enable_host_encryption = true` was added inside the `default_node_pool` block. This instructs Azure to encrypt temp disks, caches, and VM-to-storage data flows at rest and in transit for the default node pool VMs.

### Verification
Run the test `test_aks_host_encryption.py` with `pytest test_aks_host_encryption.py`. It confirms that `enable_host_encryption = true` is explicitly configured in `default_node_pool` of `azurerm_kubernetes_cluster.k8s_cluster`, satisfying `CKV_AZURE_227`.