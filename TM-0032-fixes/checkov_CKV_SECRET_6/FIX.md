### Vulnerability Details
Checkov check `CKV_SECRET_6` (Base64 High Entropy String) flagged a hardcoded secret in `terraform/azure/sql.tf`. Specifically, the resource identifier `a57ae0fe47084bc8a05f69f3f8083896f8b437b0` is the SHA-1 hash of the plaintext password `"Aa12345678"` assigned to `administrator_login_password` at line 15 (`azurerm_sql_server.example`) and line 83 (`azurerm_postgresql_server.example`). Hardcoding credentials in version control exposes sensitive database credentials to anyone with repository access and makes credential rotation impractical.

### Fix Details
Replaced hardcoded `administrator_login_password = "Aa12345678"` on lines 15 and 83 with `administrator_login_password = random_string.password.result`, aligning with how `azurerm_mysql_server.example` already dynamically manages its administrator password on line 50. This completely removes the hardcoded secret matching hash `a57ae0fe47084bc8a05f69f3f8083896f8b437b0`.

### Verification
Run `pytest test_sql_secret.py` (or `python -m unittest test_sql_secret.py`). The test fails on the original file containing the plaintext secret and passes once replaced with the dynamic reference.