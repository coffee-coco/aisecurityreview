### Vulnerability Details
`Checkov CKV_AWS_46` flags hard-coded plain-text secrets in EC2 user data. In `terraform/aws/ec2.tf`, lines 15-17 contained explicit AWS credentials within the `aws_instance.web_host` user data script:
```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMAAA
export AWS_SECRET_ACCESS_KEY=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
export AWS_DEFAULT_REGION=us-west-2
```
EC2 user data is stored unencrypted in the EC2 instance metadata service (IMDS), is viewable via AWS API/CLI calls (`DescribeInstanceAttribute` / `user_data`), and is logged in Terraform state files. Hardcoding credentials in user data risks credential leakage to any process on the instance, anyone with read-only AWS EC2 permissions, or anyone with access to state/source repositories.

### Remediated Fix
1. Removed lines 15-17 containing `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION` from the `user_data` heredoc.
2. Removed the comment noting plain text secrets in user data on line 2.

If the instance requires AWS permissions, an IAM instance profile (`iam_instance_profile`) should be attached to the instance instead of supplying static credentials.

### Verification
Run the test via `pytest test_ec2_user_data_secrets.py` (or `python3 -m unittest test_ec2_user_data_secrets.py`). The test inspects the `user_data` block of `aws_instance.web_host` to ensure that AWS access key identifiers and `AWS_SECRET_ACCESS_KEY` variables are no longer present.