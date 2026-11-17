# Run using: pytest test_mssql_alert_policy_email_admins.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestMssqlAlertPolicyEmailAdmins(unittest.TestCase):
    TARGET_RESOURCES = [
        ("terraform/azure/mssql.tf", "alertpolicy1"),
        ("terraform/azure/mssql.tf", "alertpolicy2"),
        ("terraform/azure/mssql.tf", "alertpolicy3"),
        ("terraform/azure/mssql.tf", "alertpolicy4"),
        ("terraform/azure/mssql.tf", "alertpolicy5"),
        ("terraform/azure/mssql.tf", "alertpolicy6"),
        ("terraform/azure/mssql.tf", "alertpolicy7"),
        ("terraform/azure/sql.tf", "example"),
    ]

    def _extract_policy_blocks(self, file_path):
        full_path = REPO_ROOT / file_path
        content = full_path.read_text()
        pattern = re.compile(
            r'resource\s+"azurerm_mssql_server_security_alert_policy"\s+"([^"]+)"\s*\{([^}]+)\}',
            re.MULTILINE,
        )
        return {name: body for name, body in pattern.findall(content)}

    def test_email_account_admins_enabled(self):
        for file_rel_path, res_name in self.TARGET_RESOURCES:
            blocks = self._extract_policy_blocks(file_rel_path)
            self.assertIn(
                res_name,
                blocks,
                f"Resource azurerm_mssql_server_security_alert_policy.{res_name} not found in {file_rel_path}",
            )
            block_body = blocks[res_name]
            match = re.search(r'email_account_admins\s*=\s*true\b', block_body)
            self.assertIsNotNone(
                match,
                f"Resource azurerm_mssql_server_security_alert_policy.{res_name} in "
                f"{file_rel_path} must have 'email_account_admins = true' (CKV_AZURE_27)",
            )


if __name__ == "__main__":
    unittest.main()