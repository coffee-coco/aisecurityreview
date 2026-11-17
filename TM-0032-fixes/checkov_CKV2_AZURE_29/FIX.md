### Vulnerability
The Azure Kubernetes Service (AKS) cluster `azurerm_kubernetes_cluster.k8s_cluster` in `terraform/azure/aks.tf` did not configure a `network_profile` block, defaulting to `kubenet` networking instead of Azure CNI. This fails Checkov policy `CKV2_AZURE_29` ("Ensure AKS cluster has Azure CNI networking enabled").

### Impact
With default `kubenet` networking, pods are placed on an internal private subnet and use NAT to communicate outside the node, preventing pods from directly participating in the Azure Virtual Network. Azure CNI gives each pod a dedicated IP from the VNet subnet, enabling native Azure network policies, fine-grained network security groups (NSGs), direct connectivity to VNet resources, and advanced enterprise network security controls.

### Remediation
Added a `network_profile` block to `azurerm_kubernetes_cluster.k8s_cluster`:
```hcl
  network_profile {
    network_plugin = "azure"
  }
```
This explicitly configures the AKS cluster to use Azure CNI networking.

### Verification
Run the test `pytest test_aks_azure_cni.py` or run `checkov -f terraform/azure/aks.tf --check CKV2_AZURE_29`.