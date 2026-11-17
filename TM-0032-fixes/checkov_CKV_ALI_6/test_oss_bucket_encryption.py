# Run with: pytest test_oss_bucket_encryption.py (from repository root, or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestOSSBucketEncryption(unittest.TestCase):
    def _extract_resource_block(self, file_path: pathlib.Path, resource_type: str, resource_name: str) -> str:
        self.assertTrue(file_path.exists(), f"Configuration file does not exist: {file_path}")
        content = file_path.read_text()
        pattern = rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{([\s\S]*?)\n\}}'
        match = re.search(pattern, content)
        self.assertIsNotNone(match, f"Resource {resource_type}.{resource_name} not found in {file_path}")
        return match.group(1)

    def test_bad_bucket_encrypted_with_cmk(self):
        bucket_tf = REPO_ROOT / "terraform/alicloud/bucket.tf"
        block = self._extract_resource_block(bucket_tf, "alicloud_oss_bucket", "bad_bucket")
        self.assertRegex(
            block,
            r'server_side_encryption_rule\s*\{[^\}]*kms_master_key_id\s*=',
            "alicloud_oss_bucket.bad_bucket must define server_side_encryption_rule with kms_master_key_id",
        )

    def test_trail_bucket_encrypted_with_cmk(self):
        trail_tf = REPO_ROOT / "terraform/alicloud/trail.tf"
        block = self._extract_resource_block(trail_tf, "alicloud_oss_bucket", "trail")
        self.assertRegex(
            block,
            r'server_side_encryption_rule\s*\{[^\}]*kms_master_key_id\s*=',
            "alicloud_oss_bucket.trail must define server_side_encryption_rule with kms_master_key_id",
        )


if __name__ == "__main__":
    unittest.main()