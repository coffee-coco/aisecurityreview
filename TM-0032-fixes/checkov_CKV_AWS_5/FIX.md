### Vulnerability Details
Checkov rule `CKV_AWS_5` flags AWS Elasticsearch / OpenSearch domains where data encryption at rest is not explicitly enabled. In `terraform/aws/es.tf`, `aws_elasticsearch_domain.monitoring-framework` omitted the `encrypt_at_rest` configuration block. When omitted, AWS Elasticsearch defaults to storing domain indices, logs, and snapshot data unencrypted on the underlying EBS volumes and storage nodes.

### Remediation
Added the `encrypt_at_rest` block with `enabled = true` to `aws_elasticsearch_domain.monitoring-framework` in `terraform/aws/es.tf`:
```hcl
  encrypt_at_rest {
    enabled = true
  }
```
This ensures that data stored within the Elasticsearch cluster is encrypted at rest using KMS encryption.

### Verification
The unit test in `test_es_encryption_at_rest.py` inspects `terraform/aws/es.tf` and verifies that the `monitoring-framework` domain resource contains an `encrypt_at_rest` block with `enabled = true`. You can also verify the remediation by running Checkov:
```bash
checkov -f terraform/aws/es.tf --check CKV_AWS_5
```