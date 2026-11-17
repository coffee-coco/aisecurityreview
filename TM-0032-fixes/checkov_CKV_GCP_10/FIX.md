### Vulnerability
Checkov rule `CKV_GCP_10` flags GKE node pools that do not have automated node upgrades enabled. When automatic node upgrades are disabled or omitted, worker nodes in the cluster do not automatically receive security patches, bug fixes, or updated Kubernetes minor/patch releases aligned with the control plane. This exposes the cluster to known Common Vulnerabilities and Exposures (CVEs) in both Kubernetes and node host operating systems.

### Evidence
In `terraform/gcp/gke.tf` lines 24–31, `google_container_node_pool.custom_node_pool` defined only `cluster`, `location`, and `node_config`, omitting the `management` block with `auto_upgrade = true`.

### Remediation
A `management` block was added to `google_container_node_pool.custom_node_pool` with `auto_upgrade = true`. This instructs GKE to keep worker nodes up to date with the cluster control plane version automatically.

### Verification
- Run the included test: `pytest test_gke_node_pool_auto_upgrade.py`.
- Run Checkov against the updated configuration: `checkov -f terraform/gcp/gke.tf -c CKV_GCP_10`.