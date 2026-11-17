# Run using: pytest test_s3_public_access_block.py
# Or: python -m unittest test_s3_public_access_block.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def parse_public_access_blocks(content: str):
    """
    Extract aws_s3_bucket_public_access_block resources from Terraform content.
    Returns a dict mapping bucket target reference to dict of attributes.
    """
    pab_pattern = re.compile(
        r'resource\s+"aws_s3_bucket_public_access_block"\s+"([^"]+)"\s*\{(.*?)\n\}',
        re.DOTALL,
    )
    blocks = {}
    for match in pab_pattern.finditer(content):
        block_body = match.group(2)
        bucket_match = re.search(r'bucket\s*=\s*([\w\.\$\{\}]+)', block_body)
        if not bucket_match:
            continue
        bucket_ref = bucket_match.group(1).strip('"')
        block_acls = bool(re.search(r'block_public_acls\s*=\s*true', block_body))
        block_policy = bool(re.search(r'block_public_policy\s*=\s*true', block_body))
        ignore_acls = bool(re.search(r'ignore_public_acls\s*=\s*true', block_body))
        restrict_buckets = bool(re.search(r'restrict_public_buckets\s*=\s*true', block_body))
        blocks[bucket_ref] = {
            "block_public_acls": block_acls,
            "block_public_policy": block_policy,
            "ignore_public_acls": ignore_acls,
            "restrict_public_buckets": restrict_buckets,
        }
    return blocks


def find_s3_buckets(content: str):
    """Extract resource names of aws_s3_bucket from Terraform content."""
    bucket_pattern = re.compile(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"')
    return bucket_pattern.findall(content)


class TestS3BucketPublicAccessBlock(unittest.TestCase):
    def test_ec2_flowbucket_has_public_access_block(self):
        ec2_tf = REPO_ROOT / "terraform/aws/ec2.tf"
        self.assertTrue(ec2_tf.is_file(), f"File not found: {ec2_tf}")
        content = ec2_tf.read_text()
        buckets = find_s3_buckets(content)
        self.assertIn("flowbucket", buckets)

        pab_blocks = parse_public_access_blocks(content)
        target = "aws_s3_bucket.flowbucket.id"
        self.assertIn(target, pab_blocks, f"Missing public access block for {target}")
        self.assertTrue(pab_blocks[target]["block_public_acls"])
        self.assertTrue(pab_blocks[target]["block_public_policy"])
        self.assertTrue(pab_blocks[target]["ignore_public_acls"])
        self.assertTrue(pab_blocks[target]["restrict_public_buckets"])

    def test_s3_buckets_have_public_access_blocks(self):
        s3_tf = REPO_ROOT / "terraform/aws/s3.tf"
        self.assertTrue(s3_tf.is_file(), f"File not found: {s3_tf}")
        content = s3_tf.read_text()
        buckets = find_s3_buckets(content)
        expected_buckets = ["data", "financials", "operations", "data_science", "logs"]
        for b in expected_buckets:
            self.assertIn(b, buckets, f"Bucket {b} not found in {s3_tf}")

        pab_blocks = parse_public_access_blocks(content)
        for b in expected_buckets:
            target = f"aws_s3_bucket.{b}.id"
            self.assertIn(target, pab_blocks, f"Missing public access block for {target}")
            self.assertTrue(pab_blocks[target]["block_public_acls"], f"{b} missing block_public_acls")
            self.assertTrue(pab_blocks[target]["block_public_policy"], f"{b} missing block_public_policy")
            self.assertTrue(pab_blocks[target]["ignore_public_acls"], f"{b} missing ignore_public_acls")
            self.assertTrue(pab_blocks[target]["restrict_public_buckets"], f"{b} missing restrict_public_buckets")


if __name__ == "__main__":
    unittest.main()