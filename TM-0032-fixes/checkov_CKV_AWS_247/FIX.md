### Vulnerability Details
Checkov rule `CKV_AWS_247` requires that Elasticsearch domains have encryption at rest enabled and use a Customer Managed Key (CMK). In `terraform/aws/es.tf`, the resource `aws_elasticsearch_domain.monitoring-framework` was configured without an `encrypt_at_rest` block. As a result, data stored in Elasticsearch indexes and underlying EBS storage is unencrypted at rest, increasing the risk of data exposure should physical disks or snapshot storage be compromised.

### Fix
1. Added an `aws_kms_key.es_key` resource with key rotation enabled to serve as the customer managed key (CMK).
2. Configured an `encrypt_at_rest` block inside `aws_elasticsearch_domain.monitoring-framework` with `enabled = true` and `kms_key_id = aws_kms_key.es_key.arn`.

### Verification
Run the test via `pytest test_es_cmk_encryption.py` (or `python3 -m unittest test_es_cmk_encryption.py`). It verifies that `aws_elasticsearch_domain.monitoring-framework` contains an `encrypt_at_rest` block with `enabled = true` and `kms_key_id` referencing a defined `aws_kms_key` resource.