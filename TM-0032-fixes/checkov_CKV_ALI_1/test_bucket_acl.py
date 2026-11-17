# Run with: pytest test_bucket_acl.py from the root of the reviewed repository
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAlicloudBucketAcl(unittest.TestCase):
    def test_bad_bucket_acl_is_private(self):
        bucket_tf_path = REPO_ROOT / "terraform" / "alicloud" / "bucket.tf"
        self.assertTrue(bucket_tf_path.is_file(), f"{bucket_tf_path} does not exist")

        content = bucket_tf_path.read_text()
        # Match resource "alicloud_oss_bucket" "bad_bucket" block
        resource_match = re.search(
            r'resource\s+"alicloud_oss_bucket"\s+"bad_bucket"\s*\{(?P<body>[\s\S]*?)\n\}',
            content,
        )
        self.assertIsNotNone(resource_match, "Could not find bad_bucket resource block")

        body = resource_match.group("body")
        acl_match = re.search(r'acl\s*=\s*"([^"]+)"', body)
        self.assertIsNotNone(acl_match, "bad_bucket does not define an acl attribute")
        acl_value = acl_match.group(1)

        # CKV_ALI_1 requires ACL to be private and not public-read / public-read-write
        self.assertNotIn(
            acl_value,
            ["public-read", "public-read-write"],
            f"Bucket acl is public: {acl_value}",
        )
        self.assertEqual(acl_value, "private", f"Bucket acl should be 'private', got: {acl_value}")


if __name__ == "__main__":
    unittest.main()