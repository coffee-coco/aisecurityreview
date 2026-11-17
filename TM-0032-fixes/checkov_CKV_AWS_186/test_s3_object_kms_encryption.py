# Run via: pytest test_s3_object_kms_encryption.py from REPO_ROOT
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_hcl_resource(content: str, resource_type: str, resource_name: str) -> str:
    header = f'resource "{resource_type}" "{resource_name}"'
    start_idx = content.find(header)
    if start_idx == -1:
        return ""
    open_brace_idx = content.find("{", start_idx)
    if open_brace_idx == -1:
        return ""
    depth = 0
    for idx in range(open_brace_idx, len(content)):
        if content[idx] == "{":
            depth += 1
        elif content[idx] == "}":
            depth -= 1
            if depth == 0:
                return content[open_brace_idx + 1:idx]
    return ""


class TestS3BucketObjectKMSEncryption(unittest.TestCase):
    def test_aws_s3_bucket_object_data_object_kms_encrypted(self):
        s3_tf_path = REPO_ROOT / "terraform" / "aws" / "s3.tf"
        self.assertTrue(s3_tf_path.exists(), f"File not found: {s3_tf_path}")
        content = s3_tf_path.read_text()

        block = extract_hcl_resource(content, "aws_s3_bucket_object", "data_object")
        self.assertTrue(block, "Resource aws_s3_bucket_object.data_object was not found")

        sse_match = re.search(r'server_side_encryption\s*=\s*"aws:kms"', block)
        self.assertIsNotNone(
            sse_match,
            "aws_s3_bucket_object.data_object must specify server_side_encryption = \"aws:kms\"",
        )

        kms_match = re.search(r'kms_key_id\s*=\s*(\S+)', block)
        self.assertIsNotNone(
            kms_match,
            "aws_s3_bucket_object.data_object must specify a customer-managed KMS key in kms_key_id",
        )


if __name__ == "__main__":
    unittest.main()