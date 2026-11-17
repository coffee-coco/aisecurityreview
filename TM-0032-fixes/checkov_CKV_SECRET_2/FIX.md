### Vulnerability Description
Checkov rule `CKV_SECRET_2` detects plain text, hardcoded AWS Access Keys (`AKIA...`) embedded in source code and Infrastructure as Code configurations. Hardcoded credentials committed to version control can be leaked or exposed to unauthorized parties, leading to potential compromise of cloud environments and data.

### Evidence Analysis
Hardcoded credentials were found across three Terraform configuration files:
1. `terraform/aws/ec2.tf` (lines 15-16): The EC2 `user_data` script contained `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMAAA` and `export AWS_SECRET_ACCESS_KEY=...`.
2. `terraform/aws/lambda.tf` (lines 45-46): The `aws_lambda_function.analysis_lambda` resource configured plain text `access_key` and `secret_key` in the `environment` variables block.
3. `terraform/aws/providers.tf` (lines 10-11): The `provider "aws"` block with alias `plain_text_access_keys_provider` contained hardcoded `access_key` and `secret_key` arguments.

### Remediation
- In `terraform/aws/ec2.tf`, removed the hardcoded AWS access key, secret key, and default region exports from the `user_data` script. EC2 instances should instead assume IAM roles via instance profiles when interacting with AWS APIs.
- In `terraform/aws/lambda.tf`, removed the `environment` block containing plain text credentials. Lambda functions should use their execution IAM role (`role`) for AWS permissions.
- In `terraform/aws/providers.tf`, removed the hardcoded `access_key` and `secret_key` parameters from the aliased AWS provider block.

### Verification
The included test (`test_aws_access_keys.py`) searches all three files for AWS Access Key patterns and secret key fragments. It fails against the original files containing the hardcoded keys and passes once the credentials are removed.