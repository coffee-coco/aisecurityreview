### Vulnerability Explanation
Checkov rule `CKV_GCP_18` requires that Google Kubernetes Engine (GKE) clusters do not have publicly accessible control planes (Kubernetes API endpoints). In `terraform/gcp/gke.tf`, the `google_container_cluster.workload_cluster` resource does not define a `private_cluster_config` block with `enable_private_endpoint = true`. By default, GKE assigns an external, publicly routable IP address to the cluster control plane. Public exposure of the Kubernetes API server exposes the control plane to scanning, brute-force attacks, and exploitation of any API server vulnerabilities from the public internet.

### Fix Details
A `private_cluster_config` block has been added to `google_container_cluster.workload_cluster` in `terraform/gcp/gke.tf`:
```hcl
  private_cluster_config {
    enable_private_endpoint = true
    enable_private_nodes    = true
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
```
- Setting `enable_private_endpoint = true` ensures the GKE control plane is assigned only an internal private IP address and is not exposed to the public internet, directly satisfying `CKV_GCP_18`.
- `enable_private_nodes = true` and `master_ipv4_cidr_block = "172.16.0.0/28"` are required parameters by Google Cloud Provider when configuring a private cluster with an internal control plane endpoint.

### Verification
Run the included test with `pytest test_gke_control_plane.py` or `python -m unittest test_gke_control_plane.py`. Alternatively, run `checkov -f terraform/gcp/gke.tf --check CKV_GCP_18` to confirm the check passes.