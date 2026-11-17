### Vulnerability Details
Checkov check `CKV_AWS_45` flags hard-coded secrets inside AWS Lambda environment variables. In `terraform/aws/lambda.tf` (lines 43-48), `aws_lambda_function.analysis_lambda` defined hard-coded AWS access keys (`access_key = "AKIAIOSFODNN7EXAMPLE"` and `secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`) directly in the `environment.variables` block. Storing secrets in plaintext in Terraform configuration and Lambda environment variables exposes sensitive credentials in source control, build logs, and the AWS console, violating credential management standards (NIST IA-5).

### Fix
The `environment` block containing the hard-coded `access_key` and `secret_key` variables was removed from `aws_lambda_function.analysis_lambda`. If credentials or configuration are needed at runtime, Lambda should assume the IAM execution role (`iam_for_lambda`) to obtain temporary credentials automatically or retrieve secrets from AWS Secrets Manager / AWS Systems Manager Parameter Store.

### Verification
Run `pytest test_lambda_secrets.py` (or `python3 -m unittest test_lambda_secrets.py`). The test parses `terraform/aws/lambda.tf` and fails if sensitive keys or AWS key IDs exist within the Lambda's environment block.