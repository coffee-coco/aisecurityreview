### Vulnerability Details
By default, Azure Kubernetes Service (AKS) clusters have local administrator accounts enabled. These accounts share a cluster-admin credential (`clusterAdmin`) that bypasses Azure Role-Based Access Control (Azure RBAC) and Microsoft Entra ID (Azure AD) authentication, preventing central auditing, MFA enforcement, and identity lifecycle management.

### Exploitation Context
In `terraform/azure/aks.tf`, `azurerm_kubernetes_cluster.k8s_cluster` did not configure the `local_account_disabled` argument. As a result, the default setting (`false`) applies. Any user with `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action` permissions can retrieve local admin kubeconfig credentials, bypassing central identity controls and audit logs.

### Remediation
Added `local_account_disabled = true` to `azurerm_kubernetes_cluster.k8s_cluster` in `terraform/azure/aks.tf`. This disables local accounts and enforces role-based access through Azure Active Directory / Azure RBAC, satisfying Checkov check `CKV_AZURE_141`.

### Verification
Run the test suite using `pytest test_aks_local_admin.py` or execute Checkov against the Terraform directory (`checkov -f terraform/azure/aks.tf --check CKV_AZURE_141`) to verify compliance.