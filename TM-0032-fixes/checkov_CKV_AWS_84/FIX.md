### Vulnerability Description
Checkov rule `CKV_AWS_84` checks that AWS Elasticsearch (and OpenSearch) domains have log publishing enabled. In the original configuration (`terraform/aws/es.tf`), the `aws_elasticsearch_domain.monitoring-framework` resource lacked any `log_publishing_options` configuration blocks. Without log publishing enabled, Elasticsearch application logs and slow logs are not captured in CloudWatch Logs, hindering security auditing, incident response, anomaly detection, and compliance with standards such as NIST AU-2, AU-3, and AU-12.

### Remediation
1. Added an `aws_cloudwatch_log_group` resource named `es_log_group` to serve as the destination log group for Elasticsearch domain logs.
2. Added `log_publishing_options` blocks to the `aws_elasticsearch_domain.monitoring-framework` resource for `INDEX_SLOW_LOGS`, `SEARCH_SLOW_LOGS`, and `ES_APPLICATION_LOGS` with `enabled = true` and pointing to `aws_cloudwatch_log_group.es_log_group.arn`.

### Verification
Run the test with `pytest test_es_logging.py` (or `python3 -m unittest test_es_logging.py`). Running Checkov (`checkov -f terraform/aws/es.tf --check CKV_AWS_84`) will now pass.