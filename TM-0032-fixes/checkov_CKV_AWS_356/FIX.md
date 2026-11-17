### Vulnerability Explanation
Checkov rule `CKV_AWS_356` verifies that IAM policy documents do not allow wildcard `"*"` as the resource for actions that can be restricted to specific ARNs. In `terraform/aws/es.tf`, `data.aws_iam_policy_document.policy` declared `actions = ["es:*"]` with `resources = ["*"]`.

Elasticsearch domain actions (`es:*`) can and should be restricted to specific Elasticsearch domain ARNs and sub-resource paths. Allowing `"*"` as the resource in an IAM policy document violates the principle of least privilege and can unintentionally broaden the scope of permissions across AWS accounts and Elasticsearch clusters.

### Fix Explanation
The fix updates `resources` in `data aws_iam_policy_document "policy"` from `["*"]` to:
```hcl
resources = [
  aws_elasticsearch_domain.monitoring-framework.arn,
  "${aws_elasticsearch_domain.monitoring-framework.arn}/*",
]
```
This restricts the policy statement specifically to the `monitoring-framework` Elasticsearch domain and its indexed paths, fulfilling `CKV_AWS_356` and adhering to AWS best practices for Elasticsearch domain access policies.

### Verification
Run the test with:
```bash
pytest test_es_policy.py
```
Or verify with Checkov directly:
```bash
checkov -f terraform/aws/es.tf --check CKV_AWS_356
```