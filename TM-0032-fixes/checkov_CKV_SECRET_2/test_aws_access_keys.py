# Run: pytest test_aws_access_keys.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

# Regex pattern matching standard AWS Access Key IDs (e.g. AKIA...)
AWS_ACCESS_KEY_REGEX = re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b")


class TestAwsAccessKeys(unittest.TestCase):
    AFFECTED_FILES = [
        "terraform/aws/ec2.tf",
        "terraform/aws/lambda.tf",
        "terraform/aws/providers.tf",
    ]

    def test_no_hardcoded_aws_access_keys(self):
        """Verify that no hardcoded AWS Access Keys or Secret Keys exist in Terraform files."""
        for rel_path in self.AFFECTED_FILES:
            file_path = REPO_ROOT / rel_path
            self.assertTrue(file_path.exists(), f"File does not exist: {file_path}")
            content = file_path.read_text()

            matches = AWS_ACCESS_KEY_REGEX.findall(content)
            self.assertEqual(
                matches,
                [],
                f"Found hardcoded AWS Access Key(s) in {rel_path}: {matches}"
            )
            self.assertNotIn(
                "wJalrXUtnFEMI",
                content,
                f"Found hardcoded AWS Secret Access Key in {rel_path}"
            )


if __name__ == "__main__":
    unittest.main()