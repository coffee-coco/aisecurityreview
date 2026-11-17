### Vulnerability Analysis
Checkov rule `CKV_AZURE_4` checks whether Azure Kubernetes Service (AKS) clusters have logging to Azure Monitor configured. In `terraform/azure/aks.tf`, `azurerm_kubernetes_cluster.k8s_cluster` configured the `addon_profile.oms_agent` block with `enabled = false`.

Without Azure Monitor / OMS agent integration enabled on the cluster, container metrics, stdout/stderr logs, and control plane diagnostics are not automatically collected into Azure Log Analytics. In the event of cluster compromise, suspicious workloads, or failure incidents, security operations and administrators lack critical audit trails and diagnostic data necessary for threat detection and incident response.

### Remediation
In `terraform/azure/aks.tf`, `addon_profile.oms_agent.enabled` was updated from `false` to `true`. This enables the OMS agent addon on the AKS cluster so logs and monitoring telemetry are streamed to Azure Monitor / Log Analytics.