### Vulnerability Details
Checkov rule `CKV_GCP_111` enforces that Google Cloud SQL PostgreSQL database instances configure the `log_statement` database flag to ensure SQL statements are logged. In `terraform/gcp/big_data.tf`, `google_sql_database_instance.master_instance` was defined without the `log_statement` flag in its `settings` block. Without statement logging enabled, database queries and schema modifications are not captured in Cloud Logging, impeding forensic auditing, incident investigation, and compliance with standards such as NIST AU-2, AU-3, and AU-12.

### Fix Details
Inside `settings` for `google_sql_database_instance.master_instance`, a `database_flags` block was added:
```hcl
    database_flags {
      name  = "log_statement"
      value = "all"
    }
```
Setting `log_statement` to `"all"` logs all SQL statements executed against the database, satisfying the Checkov check requirement (`"all"`, `"ddl"`, or `"mod"`).

### Verification
1. Run `pytest test_sql_log_statement.py` or `python -m unittest test_sql_log_statement.py`. The test parses `terraform/gcp/big_data.tf` and verifies that the `master_instance` resource declares the `log_statement` flag with an accepted value (`all`, `ddl`, or `mod`).
2. Run Checkov against the Terraform directory (`checkov -f terraform/gcp/big_data.tf -c CKV_GCP_111`) to ensure the check passes.