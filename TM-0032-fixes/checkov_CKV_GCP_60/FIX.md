### Vulnerability
Checkov rule `CKV_GCP_60` checks that Google Cloud SQL database instances do not have a public IPv4 address assigned. Assigning a public IP address exposes the database engine directly to the public Internet, making it vulnerable to network scanning, credential brute-forcing, and direct exploitation of database protocol vulnerabilities.

### Exploitation in Evidence
In `terraform/gcp/big_data.tf` (lines 8–14):
```terraform
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "WWW"
        value = "0.0.0.0/0"
      }
    }
```
The `google_sql_database_instance.master_instance` resource explicitly configures `ipv4_enabled = true`, provisioning a publicly routable IPv4 address for the PostgreSQL database instance.

### Fix
Updated `ipv4_enabled = true` to `ipv4_enabled = false` within `ip_configuration` for `google_sql_database_instance.master_instance`. This disables the public IPv4 interface on the database instance, ensuring that public IP assignment is disabled.

### Verification
Run the test suite using `pytest test_big_data_public_ip.py` or run `checkov -f terraform/gcp/big_data.tf --check CKV_GCP_60` to confirm that the resource complies with policy.