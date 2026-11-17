# Run using: pytest test_aws_credentials_committed.py
# or with REPO_ROOT set: REPO_ROOT=/path/to/repo pytest test_aws_credentials_committed.py

import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

AWS_KEY_PATTERN = re.compile(r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])")
AWS_KEY_PREFIX = re.compile(r"AKIA[0-9A-Z]{16}")

AFFECTED_FILES = [
    "terraform/aws/ec2.tf",
    "terraform/aws/lambda.tf",
    "terraform/aws/providers.tf",
]


class TestAwsKeysNotCommitted(unittest.TestCase):
    def test_no_aws_access_keys_in_source_files(self):
        findings = []
        for rel_path in AFFECTED_FILES:
            file_path = REPO_ROOT / rel_path
            self.assertTrue(file_path.exists(), f"Expected file {rel_path} to exist")
            content = file_path.read_text()
            matches = AWS_KEY_PREFIX.findall(content)
            if matches:
                findings.append(f"{rel_path}: found AWS access key(s) {matches}")

        self.assertEqual(
            [],
            findings,
            f"Committed AWS access keys were detected in the source:\n" + "\n".join(findings),
        )


if __name__ == "__main__":
    unittest.main()