# Run via: pytest test_bucket_cmk_encryption.py (or python -m unittest test_bucket_cmk_encryption.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def _extract_resource_block(content: str, resource_type: str, resource_name: str) -> str:
    header = f'resource "{resource_type}" "{resource_name}"' 
    start_idx = content.find(header)
    if start_idx == -1:
        return ""
    open_brace_idx = content.find("{", start_idx)
    if open_brace_idx == -1:
        return ""
    brace_count = 0
    body_start = open_brace_idx + 1
    for idx in range(open_brace_idx, len(content)):
        char = content[idx]
        if char == "{":
            brace_count += 1
        elif char == "}":
            brace_count -= 1
            if brace_count == 0:
                return content[body_start:idx]
    return ""


class TestOCIObjectStorageCMK(unittest.TestCase):
    def test_bucket_encrypted_with_customer_managed_key(self):
        bucket_tf_path = REPO_ROOT / "terraform/oracle/bucket.tf"
        self.assertTrue(bucket_tf_path.exists(), f"Expected file {bucket_tf_path} to exist.")

        content = bucket_tf_path.read_text(encoding="utf-8")
        bucket_block = _extract_resource_block(content, "oci_objectstorage_bucket", "secretsquirrel")
        self.assertTrue(bucket_block, "Resource oci_objectstorage_bucket.secretsquirrel not found.")

        kms_match = re.search(r'^\s*kms_key_id\s*=\s*["\']?([^"\'\s]+)["\']?', bucket_block, re.MULTILINE)
        self.assertIsNotNone(
            kms_match,
            "oci_objectstorage_bucket.secretsquirrel is missing kms_key_id (CKV_OCI_9 requirement)"
        )
        self.assertTrue(
            bool(kms_match.group(1).strip()),
            "kms_key_id must not be empty"
        )


if __name__ == "__main__":
    unittest.main()