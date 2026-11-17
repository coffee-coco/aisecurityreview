### Vulnerability Analysis
Hardcoding AWS credentials (`access_key` and `secret_key`) directly in Terraform configuration files violates security best practices (Checkov policy `CKV_AWS_41`, NIST IA-5). In `terraform/aws/providers.tf`, lines 10-11 contained hardcoded credentials (`AKIAIOSFODNN7EXAMPLE` and `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`) within the `plain_text_access_keys_provider` provider block. If committed to version control, static credentials can easily leak, leading to unauthorized AWS account access and credential exposure.

### Fix Details
Removed the static `access_key` and `secret_key` attributes from the `aws.plain_text_access_keys_provider` block in `terraform/aws/providers.tf`. Authentication should instead rely on the standard AWS credential resolution chain (such as IAM roles, AWS profiles, or environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`).

### Verification
The regression test in `test_aws_provider_keys.py` scans `terraform/aws/providers.tf` to verify that no static `access_key` or `secret_key` definitions exist in the configuration. The test fails on the original code and succeeds with the hardcoded credentials removed.