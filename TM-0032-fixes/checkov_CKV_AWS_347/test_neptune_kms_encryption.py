# Run via: pytest test_neptune_kms_encryption.py (from repo root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestNeptuneClusterKmsEncryption(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform/aws/neptune.tf"
        self.assertTrue(self.tf_file.exists(), f"{self.tf_file} does not exist")
        self.content = self.tf_file.read_text()

    def test_neptune_cluster_uses_customer_managed_kms_key(self):
        cluster_match = re.search(
            r'resource\s+"aws_neptune_cluster"\s+"default"\s*{(?P<body>[\s\S]*?)^}',
            self.content,
            re.MULTILINE,
        )
        self.assertIsNotNone(cluster_match, "aws_neptune_cluster.default not found")
        body = cluster_match.group("body")

        # storage_encrypted must be set to true
        storage_encrypted = re.search(r'storage_encrypted\s*=\s*(\w+)', body)
        self.assertIsNotNone(storage_encrypted, "storage_encrypted is not specified")
        self.assertEqual(
            storage_encrypted.group(1),
            "true",
            f"storage_encrypted must be true, got {storage_encrypted.group(1)}",
        )

        # kms_key_arn must be specified for CKV_AWS_347
        kms_key = re.search(r'kms_key_arn\s*=\s*([\w\.\"\-]+)', body)
        self.assertIsNotNone(
            kms_key,
            "kms_key_arn must be configured on aws_neptune_cluster.default to satisfy CKV_AWS_347",
        )
        self.assertNotEqual(kms_key.group(1).strip('"'), "", "kms_key_arn cannot be empty")

        # Ensure the customer-managed key resource is defined in the configuration
        kms_resource_match = re.search(r'resource\s+"aws_kms_key"\s+"\w+"', self.content)
        self.assertIsNotNone(
            kms_resource_match,
            "A customer-managed KMS key resource (aws_kms_key) must be defined",
        )


if __name__ == "__main__":
    unittest.main()