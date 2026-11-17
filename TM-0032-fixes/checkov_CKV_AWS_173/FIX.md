### Vulnerability Explanation
Checkov rule `CKV_AWS_173` checks whether AWS Lambda functions that define environment variables use an AWS Key Management Service (KMS) Customer Managed Key (CMK) via the `kms_key_arn` parameter to encrypt environment variables at rest. 

In `terraform/aws/lambda.tf`, the resource `aws_lambda_function.analysis_lambda` configures an `environment` block with sensitive credentials (`access_key` and `secret_key`), but does not set `kms_key_arn`. By default, when `kms_key_arn` is omitted, AWS Lambda encrypts environment variables using a default service key (`aws/lambda`). Default AWS-managed keys do not provide organizational control over key rotation, access policies, audit logging, or separation of duties, violating NIST SC-13 and SC-28 requirements.

### Remediation
1. Added an `aws_kms_key.lambda_kms` resource in `terraform/aws/lambda.tf` with key rotation enabled (`enable_key_rotation = true`).
2. Updated `aws_lambda_function.analysis_lambda` to configure `kms_key_arn = aws_kms_key.lambda_kms.arn`.

### Verification
- Run `pytest test_lambda_encryption.py` to confirm that the `analysis_lambda` resource defines `kms_key_arn`.
- Run Checkov (`checkov -f terraform/aws/lambda.tf --check CKV_AWS_173`) to confirm the check passes.