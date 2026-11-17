# Run tests with: pytest test_sql_log_statement.py (or python -m unittest test_sql_log_statement.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestGcpPostgresLogStatement(unittest.TestCase):
    def test_postgres_log_statement_flag_configured(self):
        config_path = REPO_ROOT / "terraform/gcp/big_data.tf"
        self.assertTrue(config_path.exists(), f"{config_path} does not exist")

        content = config_path.read_text()

        # Locate the google_sql_database_instance.master_instance resource block
        resource_match = re.search(
            r'resource\s+"google_sql_database_instance"\s+"master_instance"\s+\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            resource_match,
            "Could not find google_sql_database_instance.master_instance resource",
        )
        resource_body = resource_match.group(1)

        # Find database_flags blocks within the resource
        flag_pattern = re.compile(
            r'database_flags\s*\{[^}]*name\s*=\s*"([^"]+)"[^}]*value\s*=\s*"([^"]+)"[^}]*\}',
            re.DOTALL,
        )
        flags = {
            name: val for name, val in flag_pattern.findall(resource_body)
        }

        self.assertIn(
            "log_statement",
            flags,
            "CKV_GCP_111 violation: database_flag 'log_statement' is missing in master_instance",
        )
        self.assertIn(
            flags["log_statement"],
            ["ddl", "mod", "all"],
            f"database_flag 'log_statement' must be one of 'ddl', 'mod', or 'all', got '{flags['log_statement']}'",
        )


if __name__ == "__main__":
    unittest.main()