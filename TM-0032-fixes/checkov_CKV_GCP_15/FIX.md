### Vulnerability Details
In Google Cloud Platform (GCP), granting access to the special group `allAuthenticatedUsers` or `allUsers` on a BigQuery dataset exposes the dataset and its tables to any entity on the internet with a Google account (or anyone anonymously in the case of `allUsers`). This triggers Checkov policy `CKV_GCP_15` ("Ensure that BigQuery datasets are not anonymously or publicly accessible").

### Evidence
In `terraform/gcp/big_data.tf`, the resource `google_bigquery_dataset.dataset` configured an `access` block granting `READER` role to `allAuthenticatedUsers`:
```hcl
resource "google_bigquery_dataset" "dataset" {
  dataset_id = "terragoat_${var.environment}_dataset"
  access {
    special_group = "allAuthenticatedUsers"
    role          = "READER"
  }
...
```

### Remediation
The `special_group` parameter was updated from `allAuthenticatedUsers` to `projectReaders`. This restricts dataset read access to authorized project readers within the GCP project, removing unintended anonymous/global public read permissions.

### Verification
Run the test via `pytest test_bigquery_dataset_access.py` or execute Checkov against the Terraform directory (`checkov -f terraform/gcp/big_data.tf --check CKV_GCP_15`).