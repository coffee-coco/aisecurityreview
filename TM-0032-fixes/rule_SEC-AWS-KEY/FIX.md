### Vulnerability Description
AWS access key IDs and secret access keys were committed in plain text across several Terraform configuration files:
1. `terraform/aws/ec2.tf`: The EC2 instance user-data script set `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMAAA` and `export AWS_SECRET_ACCESS_KEY=...`.
2. `terraform/aws/lambda.tf`: The Lambda environment variables block exposed `access_key = "AKIAIOSFODNN7EXAMPLE"` and `secret_key = "..."`.
3. `terraform/aws/providers.tf`: The AWS provider aliased as `plain_text_access_keys_provider` configured hard-coded `access_key = "AKIAIOSFODNN7EXAMPLE"` and `secret_key = "..."`.

Hard-coding long-lived AWS IAM credentials into source code risks credential exposure via version control history, log aggregation, instance metadata/user-data inspection, and Lambda function introspection, potentially leading to unauthorized cloud infrastructure access.

### Fix Details
- In `terraform/aws/ec2.tf`, removed the hard-coded `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variable exports from the EC2 `user_data` script. EC2 instances should instead assume IAM roles via instance profiles (`aws_iam_instance_profile`).
- In `terraform/aws/lambda.tf`, removed the `environment` block setting `access_key` and `secret_key`. Lambda execution should rely on the IAM execution role attached to the function (`aws_iam_role.iam_for_lambda`).
- In `terraform/aws/providers.tf`, removed the static `access_key` and `secret_key` attributes from the provider block so that it relies on standard AWS credential provider chains (environment variables, profile configurations, or IAM assumed roles).

### Verification
The regression test in `test_aws_credentials_committed.py` scans each of the affected files for AWS access key patterns (`AKIA[0-9A-Z]{16}`). It fails against the original code containing the hard-coded credentials and passes once the access keys are removed.