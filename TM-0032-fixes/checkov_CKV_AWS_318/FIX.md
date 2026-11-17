### Vulnerability
Checkov rule `CKV_AWS_318` checks that AWS Elasticsearch/OpenSearch domains are configured with dedicated master nodes enabled (`dedicated_master_enabled = true`) and at least 3 dedicated master nodes (`dedicated_master_count >= 3`).

Without dedicated master nodes, data nodes take on cluster management tasks. If a data node experiences high CPU or memory load, cluster management operations (node discovery, shard allocation, state updates) can stall or fail, increasing the risk of split-brain scenarios and cluster downtime. Furthermore, setting fewer than three dedicated master nodes prevents establishing a reliable quorum for master elections.

### Evidence
In `terraform/aws/es.tf`, lines 8-10:
```hcl
    dedicated_master_enabled = false
    dedicated_master_type    = "m4.large.elasticsearch"
    dedicated_master_count   = 1
```
`dedicated_master_enabled` was set to `false`, and `dedicated_master_count` was set to `1`.

### Fix
Updated `terraform/aws/es.tf` within `aws_elasticsearch_domain.monitoring-framework.cluster_config`:
- Set `dedicated_master_enabled = true`
- Set `dedicated_master_count   = 3`

### Verification
Run the test with `pytest test_es_dedicated_master.py` or run `checkov -f terraform/aws/es.tf --check CKV_AWS_318` to ensure the check passes.