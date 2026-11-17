### Vulnerability Description
Checkov check `CKV_AZURE_168` checks that Azure Kubernetes Service (AKS) node pools configure `max_pods` to at least 50. When `max_pods` is omitted or set below 50, node scheduling capacity may be restricted or default to provider/networking-dependent minimums (e.g., 30 pods for Azure CNI), leading to suboptimal resource density, pod scheduling failures, or unnecessary cluster horizontal scaling.

### Evidence
In `terraform/azure/aks.tf` lines 9-13:
```hcl
  default_node_pool {
    name       = "default"
    vm_size    = "Standard_D2_v2"
    node_count = 2
  }
```
The `default_node_pool` block did not define `max_pods`.

### Remediation
Added `max_pods = 50` within `default_node_pool` in `terraform/azure/aks.tf`. This satisfies the minimum pod count requirement recommended by security baselines and Checkov rule `CKV_AZURE_168`.

### Verification
Run `pytest test_aks_max_pods.py` or run `checkov -f terraform/azure/aks.tf --check CKV_AZURE_168` to verify compliance.