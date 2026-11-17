# Run using: pytest test_s3_kms_encryption.py (or python -m unittest test_s3_kms_encryption.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_resource_blocks(content: str, resource_type: str) -> dict:
    """Extract resource blocks of a given type and return a mapping of name to block content."""
    pattern = re.compile(rf'resource\s+"{resource_type}"\s+"([^"]+)"\s*\{{')
    resources = {}
    for match in pattern.finditer(content):
        name = match.group(1)
        start_idx = match.end()
        depth = 1
        i = start_idx
        while i < len(content) and depth > 0:
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
            i += 1
        resources[name] = content[start_idx : i - 1]
    return resources


class TestS3KMSEncryption(unittest.TestCase):
    def _assert_bucket_has_kms_encryption(self, bucket_name: str, block_content: str):
        self.assertIn(
            "server_side_encryption_configuration",
            block_content,
            f"Bucket '{bucket_name}' missing server_side_encryption_configuration block",
        )
        self.assertRegex(
            block_content,
            r'sse_algorithm\s*=\s*"aws:kms"',
            f"Bucket '{bucket_name}' does not specify sse_algorithm = \"aws:kms\"",
        )

    def test_ec2_flowbucket_encrypted_with_kms(self):
        ec2_file = REPO_ROOT / "terraform/aws/ec2.tf"
        self.assertTrue(ec2_file.is_file(), f"File not found: {ec2_file}")
        content = ec2_file.read_text()
        buckets = extract_resource_blocks(content, "aws_s3_bucket")
        self.assertIn("flowbucket", buckets, "Resource aws_s3_bucket.flowbucket not found in ec2.tf")
        self._assert_bucket_has_kms_encryption("flowbucket", buckets["flowbucket"])

    def test_s3_buckets_encrypted_with_kms(self):
        s3_file = REPO_ROOT / "terraform/aws/s3.tf"
        self.assertTrue(s3_file.is_file(), f"File not found: {s3_file}")
        content = s3_file.read_text()
        buckets = extract_resource_blocks(content, "aws_s3_bucket")
        expected_buckets = ["data", "financials", "operations", "data_science", "logs"]
        for bucket_name in expected_buckets:
            self.assertIn(bucket_name, buckets, f"Resource aws_s3_bucket.{bucket_name} not found in s3.tf")
            self._assert_bucket_has_kms_encryption(bucket_name, buckets[bucket_name])


if __name__ == "__main__":
    unittest.main()