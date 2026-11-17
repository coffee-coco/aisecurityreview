### Vulnerability Description
Checkov rule `CKV_OCI_9` enforces that Oracle Cloud Infrastructure (OCI) Object Storage buckets are encrypted using a Customer Managed Key (CMK) hosted in OCI Vault / KMS. By default, OCI Object Storage encrypts data using Oracle-managed master keys. While data is encrypted at rest, using Oracle-managed keys prevents organizations from retaining direct control over key rotation, lifecycle management, and cryptographic boundary access controls.

### Evidence
In `terraform/oracle/bucket.tf` (lines 1–23), the `oci_objectstorage_bucket.secretsquirrel` resource was declared without the `kms_key_id` attribute, leaving the bucket encrypted with standard provider-managed keys.

### Fix
The `kms_key_id` property was added to `oci_objectstorage_bucket.secretsquirrel` pointing to an OCI KMS Master Encryption Key OCID (`ocid1.key.oc1..exampleuniqueID`). This instructs OCI Object Storage to use a customer-managed KMS key for server-side encryption of bucket contents, satisfying `CKV_OCI_9`.

### Verification
The regression test in `test_bucket_cmk_encryption.py` checks that `oci_objectstorage_bucket.secretsquirrel` defines a non-empty `kms_key_id`. It fails against the original code where `kms_key_id` is absent and passes once the property is added. You can run it with `pytest test_bucket_cmk_encryption.py` or run `checkov -f terraform/oracle/bucket.tf --check CKV_OCI_9`.