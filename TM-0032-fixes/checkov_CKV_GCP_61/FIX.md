### Vulnerability Details
Checkov rule `CKV_GCP_61` requires that intra-node visibility be enabled for Google Kubernetes Engine (GKE) clusters. Without intra-node visibility, network traffic between pods hosted on the same node is handled entirely by local virtual bridges and kernel packet routing on the node itself. As a result, this pod-to-pod traffic does not traverse the VPC network layer, making it completely invisible to VPC Flow Logs and firewall rules, impairing network monitoring, auditing, and threat detection.

### Evidence
In `terraform/gcp/gke.tf` lines 6-22, `google_container_cluster.workload_cluster` did not specify `enable_intranode_visibility`, causing it to default to `false`:
```hcl
resource "google_container_cluster" "workload_cluster" {
  name               = "terragoat-${var.environment}-cluster"
  logging_service    = "none"
  location           = var.region
  ...
}
```

### Fix Details
Configured `enable_intranode_visibility = true` on `google_container_cluster.workload_cluster`. This ensures all intra-node pod communications are routed through the VPC network and can be captured by VPC Flow Logs.

### Verification
Run the test with `pytest test_gke_intranode_visibility.py` (or `python3 -m unittest test_gke_intranode_visibility.py`). Running checkov against the Terraform directory (`checkov -f terraform/gcp/gke.tf --check CKV_GCP_61`) will also verify that the check now passes.