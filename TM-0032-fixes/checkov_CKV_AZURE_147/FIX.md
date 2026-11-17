### Vulnerability Details
In Azure Database for PostgreSQL (`azurerm_postgresql_server`), connections default to older or disabled TLS enforcement (`TLSEnforcementDisabled`) unless `ssl_minimal_tls_version_enforced` is explicitly defined. Older TLS versions (TLS 1.0 and TLS 1.1) have known security flaws and vulnerabilities (e.g., POODLE, BEAST) and are deprecated by modern security standards (NIST SP 800-52r2, PCI DSS).

Checkov check `CKV_AZURE_147` verifies that the `ssl_minimal_tls_version_enforced` parameter in `azurerm_postgresql_server` is explicitly configured to `"TLS1_2"`.

### Fix Details
In `terraform/azure/sql.tf`, `ssl_minimal_tls_version_enforced = "TLS1_2"` was added to `azurerm_postgresql_server.example`.

### Verification
Run the test `pytest test_azure_postgresql_tls.py` or run `checkov -f terraform/azure/sql.tf --check CKV_AZURE_147` to confirm the check passes.