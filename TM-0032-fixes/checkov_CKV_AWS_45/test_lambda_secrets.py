# Run: pytest test_lambda_secrets.py from the root of the reviewed repository, or with REPO_ROOT set.
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestLambdaEnvironmentSecrets(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform/aws/lambda.tf"
        self.assertTrue(self.tf_file.exists(), f"File {self.tf_file} does not exist")
        self.content = self.tf_file.read_text()

    def test_no_hardcoded_secrets_in_lambda(self):
        match = re.search(
            r'resource\s+"aws_lambda_function"\s+"analysis_lambda"\s+{(.*?)\n}',
            self.content,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "aws_lambda_function.analysis_lambda resource not found")
        lambda_block = match.group(1)

        env_match = re.search(r'environment\s+{(.*?)}', lambda_block, re.DOTALL)
        if env_match:
            env_content = env_match.group(1)
            self.assertNotRegex(
                env_content,
                r'AKIA[0-9A-Z]{16}',
                "Found hard-coded AWS access key ID in Lambda environment variables",
            )
            self.assertNotRegex(
                env_content,
                r'(?i)(access_key|secret_key|password|token)\s*=',
                "Found sensitive credential keys in Lambda environment variables",
            )


if __name__ == "__main__":
    unittest.main()