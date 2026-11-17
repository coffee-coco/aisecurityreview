### Vulnerability Analysis
`aws_elasticsearch_domain.monitoring-framework` was configured without Fine-Grained Access Control (FGAC), failing Checkov rule `CKV2_AWS_52` (`Ensure AWS ElasticSearch/OpenSearch Fine-grained access control is enabled`).

Without fine-grained access control enabled via `advanced_security_options`, the Elasticsearch domain relies solely on high-level domain access policies. In this configuration, any user with access to the domain would possess broad cluster-level permissions rather than index-, document-, or field-level granular permissions.

### Remediation
In `terraform/aws/es.tf`, the `advanced_security_options` block was added to `aws_elasticsearch_domain.monitoring-framework` with `enabled = true` and master user options specified. This enforces fine-grained access control and satisfies `CKV2_AWS_52`.

### Verification
Run the test with:
```bash
pytest test_es_fine_grained_access_control.py
```
or using `unittest`:
```bash
python -m unittest test_es_fine_grained_access_control.py
```
Alternatively, run Checkov against the Terraform template:
```bash
checkov -f terraform/aws/es.tf --check CKV2_AWS_52
```