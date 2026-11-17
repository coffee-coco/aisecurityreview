### Vulnerability Explanation
AWS Lambda code signing ensures that only trusted code signed by an approved publisher can run in a Lambda function. Without code signing enabled, unauthenticated or tampered code deployments cannot be detected or blocked by AWS Lambda. Checkov policy `CKV_AWS_272` checks that `aws_lambda_function` resources have `code_signing_config_arn` configured.

In `terraform/aws/lambda.tf` (lines 32–59), the resource `aws_lambda_function.analysis_lambda` lacked the `code_signing_config_arn` property, making it vulnerable to execution of unsigned, untrusted, or tampered code artifacts.

### Fix
1. Added an AWS Signer signing profile (`aws_signer_signing_profile.analysis_profile`) using the standard platform `AWSLambda-SHA384-ECDSA`.
2. Added an AWS Lambda Code Signing Config (`aws_lambda_code_signing_config.analysis_csc`) referencing the signing profile and enforcing validation on deployment (`untrusted_artifact_on_deployment = "Enforce"`).
3. Configured `code_signing_config_arn = aws_lambda_code_signing_config.analysis_csc.arn` on `aws_lambda_function.analysis_lambda`.

### Verification
- Run `pytest test_lambda_code_signing.py` (or `python -m unittest test_lambda_code_signing.py`), which validates that `code_signing_config_arn` is configured on `aws_lambda_function.analysis_lambda`.
- Run Checkov (`checkov -f terraform/aws/lambda.tf -c CKV_AWS_272`) to verify the check passes.