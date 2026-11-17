### Vulnerability Description
Checkov rule `CKV_AWS_186` requires that S3 objects uploaded via Terraform (`aws_s3_bucket_object` or `aws_s3_object`) are encrypted using AWS KMS with a Customer Managed Key (CMK). Without KMS CMK encryption configured on the object, the object is uploaded unencrypted or relies on default bucket configurations that may not enforce CMK encryption, leaving data at risk of unauthorized access or failing compliance standards requiring cryptographic separation.

### Vulnerable Code
In `terraform/aws/s3.tf`, lines 23-40 define `aws_s3_bucket_object.data_object` without specifying server-side encryption or a KMS key:
```hcl
resource "aws_s3_bucket_object" "data_object" {
  bucket = aws_s3_bucket.data.id
  key    = "customer-master.xlsx"
  source = "resources/customer-master.xlsx"
  tags = merge({ ... })
}
```

### Remediation
We configure `aws_s3_bucket_object.data_object` with `server_side_encryption = "aws:kms"` and reference the KMS key ARN via `kms_key_id = aws_kms_key.logs_key.arn` (which is already declared in this module).

### Verification
Run `pytest test_s3_object_kms_encryption.py` or run `checkov -f terraform/aws/s3.tf --check CKV_AWS_186` to verify that the check passes.