# Run with: pytest test_lambda_code_signing.py (or python -m unittest test_lambda_code_signing.py) from repo root
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_resource_block(content: str, resource_type: str, resource_name: str) -> str:
    header = f'resource "{resource_type}" "{resource_name}"' 
    idx = content.find(header)
    if idx == -1:
        return ""
    brace_start = content.find("{", idx)
    if brace_start == -1:
        return ""
    depth = 0
    for i in range(brace_start, len(content)):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return content[brace_start + 1:i]
    return ""


class TestLambdaCodeSigning(unittest.TestCase):
    def test_analysis_lambda_code_signing_config_configured(self):
        lambda_tf_path = REPO_ROOT / "terraform/aws/lambda.tf"
        self.assertTrue(lambda_tf_path.exists(), f"Missing target file: {lambda_tf_path}")
        content = lambda_tf_path.read_text()

        block = extract_resource_block(content, "aws_lambda_function", "analysis_lambda")
        self.assertTrue(bool(block), 'Resource aws_lambda_function "analysis_lambda" not found')

        match = re.search(r"^\s*code_signing_config_arn\s*=\s*\S+", block, re.MULTILINE)
        self.assertIsNotNone(
            match,
            "aws_lambda_function.analysis_lambda must define code_signing_config_arn to satisfy CKV_AWS_272",
        )


if __name__ == "__main__":
    unittest.main()