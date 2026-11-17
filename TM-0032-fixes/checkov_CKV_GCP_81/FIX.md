### Vulnerability Explanation
By default, Google Cloud BigQuery encrypts customer content at rest using Google-managed encryption keys. However, compliance standards (such as NIST SC-13, SC-28, SC-28(1)) and Checkov policy `CKV_GCP_81` require BigQuery datasets to be configured with Customer-Managed / Customer-Supplied Encryption Keys (CMEK/CSEK) via Cloud KMS. This ensures organizations have full lifecycle control over encryption keys, including key access policies, rotation, and cryptographic revocation.

### Evidence
In `terraform/gcp/big_data.tf` lines 21-37:
```hcl
resource "google_bigquery_dataset" "dataset" {
  dataset_id = "terragoat_${var.environment}_dataset"
  access {
    special_group = "allAuthenticatedUsers"
    role          = "READER"
  }
  labels = {
    ...
  }
}
```
The `google_bigquery_dataset.dataset` resource omits the `default_encryption_configuration` block, meaning tables created within the dataset default to Google-owned encryption rather than KMS-managed keys.

### Remediation
A `default_encryption_configuration` block containing a valid Cloud KMS key name (`kms_key_name`) was added to `google_bigquery_dataset.dataset`:
```hcl
  default_encryption_configuration {
    kms_key_name = "projects/terragoat-${var.environment}/locations/${var.region}/keyRings/terragoat-keyring/cryptoKeys/terragoat-key"
  }
```
This ensures tables in the dataset inherit encryption with customer-managed keys.

### Verification
- Run the unit test: `pytest test_bigquery_dataset_encryption.py`
- Alternatively, run Checkov: `checkov -f terraform/gcp/big_data.tf --check CKV_GCP_81` to verify the check passes.