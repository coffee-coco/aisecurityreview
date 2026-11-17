# Run with: pytest test_db_encryption_in_transit.py from repo root or with REPO_ROOT set
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestRDSEncryptionInTransit(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform" / "aws" / "db-app.tf"
        self.assertTrue(self.tf_file.exists(), f"File not found: {self.tf_file}")
        self.content = self.tf_file.read_text(encoding="utf-8")

    def test_rds_instance_enforces_encryption_in_transit(self):
        """Ensure MySQL RDS instance parameter group enforces TLS via require_secure_transport."""
        self.assertIn('resource "aws_db_instance" "default"', self.content)
        self.assertIn(
            "parameter_group_name",
            self.content,
            "RDS instance should specify a parameter group",
        )

        # Check for require_secure_transport parameter inside aws_db_parameter_group
        param_pattern = re.compile(
            r'parameter\s*\{[^{}]*?name\s*=\s*"require_secure_transport"[^{}]*?value\s*=\s*"(?:ON|1)"[^{}]*?\}',
            re.DOTALL,
        )
        self.assertRegex(
            self.content,
            param_pattern,
            "aws_db_parameter_group must configure parameter 'require_secure_transport' to 'ON' or '1' for encryption in transit (CKV2_AWS_69)",
        )


if __name__ == "__main__":
    unittest.main()