### Vulnerability
Checkov rule `CKV_AWS_317` enforces that AWS Elasticsearch/OpenSearch domains have audit logging enabled. In `terraform/aws/es.tf`, the resource `aws_elasticsearch_domain.monitoring-framework` was provisioned without a `log_publishing_options` configuration block for `AUDIT_LOGS`. Without audit logging enabled, access requests, authentication attempts, authorization failures, and administrative actions against the domain are not recorded to CloudWatch Logs, violating audit compliance requirements (NIST AU-2, AU-3, AU-12) and impairing incident detection and investigation capabilities.

### Remediation
A `log_publishing_options` block was added to `aws_elasticsearch_domain.monitoring-framework` in `terraform/aws/es.tf` with `log_type = "AUDIT_LOGS"`, `enabled = true`, and a destination CloudWatch Log Group ARN configured.

### Verification
Run `pytest test_es_audit_logging.py` or execute Checkov against the Terraform directory (`checkov -f terraform/aws/es.tf --check CKV_AWS_317`) to confirm that `CKV_AWS_317` now passes.