### Vulnerability Details
Checkov rule `CKV_AZURE_171` flags Azure Kubernetes Service (AKS) clusters that do not define an automatic upgrade channel (`automatic_channel_upgrade`). When unconfigured or omitted, AKS clusters do not automatically receive Kubernetes patch or minor version updates. Over time, this leaves the cluster running outdated Kubernetes versions that are susceptible to known security vulnerabilities (CVEs) and lacking critical bug/security fixes.

### Fix Details
In `terraform/azure/aks.tf`, under the `azurerm_kubernetes_cluster.k8s_cluster` resource, added `automatic_channel_upgrade = "patch"`. The `patch` channel automatically upgrades the cluster to the latest supported patch version of Kubernetes within the current minor version, applying security and bug fixes while minimizing breaking changes.

### Verification
The unit test in `test_aks_upgrade_channel.py` parses `terraform/azure/aks.tf` and checks that the `automatic_channel_upgrade` property is configured to one of the valid upgrade channels (`patch`, `rapid`, `node-image`, `stable`). It fails against the original configuration and passes once `automatic_channel_upgrade` is configured.