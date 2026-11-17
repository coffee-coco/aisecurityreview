### Vulnerability Details
Checkov rule `CKV2_AWS_59` checks that AWS Elasticsearch and OpenSearch service domains have dedicated master nodes enabled. In production and production-like clusters, dedicated master nodes perform management tasks (such as tracking cluster state, creating indices, and allocating shards) independently of data nodes. When dedicated master nodes are disabled, data nodes perform master responsibilities in addition to handling search and index requests. Heavy search or indexing loads can cause master tasks to stall or time out, resulting in cluster instability, split-brain conditions, or service outages.

### Evidence
In `terraform/aws/es.tf` lines 5–11:
```terraform
  cluster_config {
    instance_type            = "t2.small.elasticsearch"
    instance_count           = 1
    dedicated_master_enabled = false
    dedicated_master_type    = "m4.large.elasticsearch"
    dedicated_master_count   = 1
  }
```
Here, `dedicated_master_enabled` was explicitly set to `false`.

### Remediation
In `terraform/aws/es.tf`, updated `dedicated_master_enabled = false` to `dedicated_master_enabled = true` within the `cluster_config` block of `aws_elasticsearch_domain.monitoring-framework`.

### Verification
Run the test suite via `pytest test_es_dedicated_master.py` or run `checkov -f terraform/aws/es.tf --check CKV2_AWS_59` to confirm compliance.