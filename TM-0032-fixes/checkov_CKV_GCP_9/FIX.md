### Vulnerability Details
Checkov rule `CKV_GCP_9` requires that automatic node repair is enabled for Google Kubernetes Engine (GKE) clusters and node pools. When node auto-repair is disabled or omitted, GKE cannot automatically drain and recreate unhealthy or failed nodes. If a node fails a health check due to hardware issues, kernel panics, or resource exhaustion, it remains in an unhealthy state until manual intervention, potentially degrading workload availability and causing denial-of-service conditions.

### Root Cause
In `terraform/gcp/gke.tf`, `google_container_node_pool.custom_node_pool` omitted the `management` block containing `auto_repair = true`.

### Fix
Added the `management` block to `google_container_node_pool.custom_node_pool` with `auto_repair = true`:
```hcl
  management {
    auto_repair = true
  }
```

### Verification
Run the test with `pytest test_gke_auto_repair.py` or run `checkov -f terraform/gcp/gke.tf --check CKV_GCP_9`. The test verifies that `google_container_node_pool.custom_node_pool` includes `auto_repair = true` in its `management` configuration.