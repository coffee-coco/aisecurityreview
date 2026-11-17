# Run via: pytest test_rds_not_publicly_accessible.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestRdsNotPubliclyAccessible(unittest.TestCase):
    def test_aws_db_instance_is_not_publicly_accessible(self):
        db_tf_path = REPO_ROOT / "terraform/aws/db-app.tf"
        self.assertTrue(db_tf_path.is_file(), f"File not found: {db_tf_path}")
        content = db_tf_path.read_text(encoding="utf-8")

        # Extract resource "aws_db_instance" "default" block
        match = re.search(
            r'resource\s+"aws_db_instance"\s+"default"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "resource aws_db_instance default not found")
        instance_block = match.group(1)

        # Verify publicly_accessible is set to false
        self.assertNotIn(
            "publicly_accessible     = true",
            instance_block,
            "aws_db_instance.default must not be publicly accessible (CKV_AWS_17)",
        )
        self.assertRegex(
            instance_block,
            r'publicly_accessible\s*=\s*false',
            "aws_db_instance.default must explicitly set publicly_accessible = false",
        )


if __name__ == "__main__":
    unittest.main()