# Run using: pytest test_ec2_user_data_secrets.py
# or with REPO_ROOT set: REPO_ROOT=/path/to/repo pytest test_ec2_user_data_secrets.py

import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))
EC2_TF_PATH = REPO_ROOT / "terraform" / "aws" / "ec2.tf"


class TestEC2UserDataSecrets(unittest.TestCase):
    def test_no_hardcoded_secrets_in_user_data(self):
        self.assertTrue(EC2_TF_PATH.exists(), f"File not found: {EC2_TF_PATH}")
        content = EC2_TF_PATH.read_text(encoding="utf-8")

        # Locate the aws_instance.web_host resource block
        instance_match = re.search(
            r'resource\s+"aws_instance"\s+"web_host"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(instance_match, "aws_instance.web_host resource not found")
        instance_block = instance_match.group(1)

        # Extract user_data contents
        user_data_match = re.search(
            r'user_data\s*=\s*<<EOF(.*?)EOF',
            instance_block,
            re.DOTALL,
        )
        self.assertIsNotNone(
            user_data_match, "user_data heredoc block not found in aws_instance.web_host"
        )
        user_data = user_data_match.group(1)

        # Check for AWS credentials / secret indicators (Checkov CKV_AWS_46)
        self.assertNotRegex(
            user_data,
            r"AKIA[0-9A-Z]{16}",
            "Hard-coded AWS Access Key ID found in EC2 user_data",
        )
        self.assertNotIn(
            "AWS_SECRET_ACCESS_KEY",
            user_data,
            "Hard-coded AWS_SECRET_ACCESS_KEY found in EC2 user_data",
        )
        self.assertNotIn(
            "AWS_ACCESS_KEY_ID",
            user_data,
            "Hard-coded AWS_ACCESS_KEY_ID found in EC2 user_data",
        )


if __name__ == "__main__":
    unittest.main()