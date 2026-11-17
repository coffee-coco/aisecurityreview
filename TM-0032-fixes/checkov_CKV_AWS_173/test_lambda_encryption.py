# Run with: pytest test_lambda_encryption.py (from repo root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))
LAMBDA_TF_PATH = REPO_ROOT / "terraform/aws/lambda.tf"


def extract_resource_block(tf_text: str, resource_type: str, resource_name: str) -> str:
    pattern = rf'resource\s+"{resource_type}"\s+"{resource_name}"\s*\{{'
    match = re.search(pattern, tf_text)
    if not match:
        return ""
    start = match.end() - 1
    depth = 0
    end = start
    for i in range(start, len(tf_text)):
        if tf_text[i] == "{":
            depth += 1
        elif tf_text[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    return tf_text[start : end + 1]


class TestLambdaEnvironmentKmsEncryption(unittest.TestCase):
    def test_analysis_lambda_configures_kms_key_arn(self):
        """Assert that aws_lambda_function.analysis_lambda configures kms_key_arn (CKV_AWS_173)."""
        self.assertTrue(LAMBDA_TF_PATH.exists(), f"File not found: {LAMBDA_TF_PATH}")
        content = LAMBDA_TF_PATH.read_text()

        block = extract_resource_block(content, "aws_lambda_function", "analysis_lambda")
        self.assertTrue(block, "Could not find aws_lambda_function.analysis_lambda resource block")

        # Verify environment variables exist in the resource
        self.assertIn("environment", block, "Expected environment block in analysis_lambda")

        # CKV_AWS_173 check: kms_key_arn must be specified
        kms_match = re.search(r'kms_key_arn\s*=\s*([^\s\n]+)', block)
        self.assertIsNotNone(
            kms_match,
            "aws_lambda_function.analysis_lambda does not set kms_key_arn for environment variable encryption (CKV_AWS_173)",
        )
        kms_value = kms_match.group(1).strip('"\'')
        self.assertTrue(len(kms_value) > 0, "kms_key_arn value must not be empty")


if __name__ == "__main__":
    unittest.main()