### Vulnerability Details
Checkov rule `CKV_AWS_136` flagged `aws_ecr_repository.repository` in `terraform/aws/ecr.tf` for lacking AWS KMS encryption. By default, Amazon ECR encrypts container images using Amazon S3-managed keys (`AES256`). Security compliance standards (such as NIST SC-12, SC-13, SC-28, and SC-28(1)) require using AWS Key Management Service (KMS) to ensure centralized key management, access controls via IAM policies/key policies, automated key rotation, and CloudTrail auditing for key usage.

### Root Cause & Exploitability
In `terraform/aws/ecr.tf` lines 1–18, `aws_ecr_repository.repository` omitted an `encryption_configuration` block. Without explicit KMS configuration, the repository defaults to provider-managed AES-256 server-side encryption, leaving sensitive container image layers without the access governance and cryptographic audit trails provided by KMS.

### Remediation
An `encryption_configuration` block with `encryption_type = "KMS"` was added to `aws_ecr_repository.repository` in `terraform/aws/ecr.tf`. If no specific `kms_key` ARN is supplied, AWS ECR uses the default AWS-managed KMS key for ECR (`aws/ecr`), satisfying `CKV_AWS_136` without requiring additional KMS resources.

### Verification
1. Run the included unit test (`pytest test_ecr_encryption.py` or `python -m unittest test_ecr_encryption.py`).
2. Run Checkov against the Terraform directory: `checkov -f terraform/aws/ecr.tf --check CKV_AWS_136` and verify that the check passes.