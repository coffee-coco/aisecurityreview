# Run: pytest test_bucket_public_access.py (or python -m unittest test_bucket_public_access.py) from the repository root
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestOCIBucketPublicAccess(unittest.TestCase):
    def test_secretsquirrel_bucket_is_not_public(self):
        bucket_tf_path = REPO_ROOT / "terraform/oracle/bucket.tf"
        self.assertTrue(bucket_tf_path.exists(), f"{bucket_tf_path} does not exist")

        content = bucket_tf_path.read_text()

        # Locate resource oci_objectstorage_bucket "secretsquirrel"
        pattern = re.compile(
            r'resource\s+"oci_objectstorage_bucket"\s+"secretsquirrel"\s*\{(?P<body>[\s\S]*?)\n\}',
            re.MULTILINE
        )
        match = pattern.search(content)
        self.assertIsNotNone(match, "Resource oci_objectstorage_bucket.secretsquirrel not found")

        body = match.group("body")
        access_type_match = re.search(r'access_type\s*=\s*"([^"]+)"', body)

        if access_type_match:
            access_type_value = access_type_match.group(1)
            self.assertNotIn(
                access_type_value,
                ["ObjectRead", "ObjectReadWithoutList"],
                f"Bucket access_type is set to public access: {access_type_value}"
            )
            self.assertEqual(
                access_type_value,
                "NoPublicAccess",
                f"Bucket access_type should be 'NoPublicAccess', got '{access_type_value}'"
            )


if __name__ == "__main__":
    unittest.main()