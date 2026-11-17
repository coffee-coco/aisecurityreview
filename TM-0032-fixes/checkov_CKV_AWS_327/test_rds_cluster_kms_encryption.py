# Run with: pytest test_rds_cluster_kms_encryption.py (or python -m unittest test_rds_cluster_kms_encryption.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_resources(content: str, resource_type: str) -> dict[str, str]:
    """Extract resource blocks of a given type accounting for nested braces."""
    pattern = re.compile(rf'resource\s+"{resource_type}"\s+"([^"]+)"\s*\{{')
    resources = {}
    for match in pattern.finditer(content):
        res_name = match.group(1)
        start = match.end()
        brace_count = 1
        pos = start
        while pos < len(content) and brace_count > 0:
            if content[pos] == "{":
                brace_count += 1
            elif content[pos] == "}":
                brace_count -= 1
            pos += 1
        resources[res_name] = content[start : pos - 1]
    return resources


class TestRDSClusterKMSEncryption(unittest.TestCase):
    def setUp(self):
        self.rds_file = REPO_ROOT / "terraform/aws/rds.tf"
        self.assertTrue(self.rds_file.exists(), f"File {self.rds_file} not found")
        self.content = self.rds_file.read_text()

    def test_all_rds_clusters_encrypted_with_kms_cmk(self):
        clusters = extract_resources(self.content, "aws_rds_cluster")
        expected_clusters = [f"app{i}-rds-cluster" for i in range(1, 10)]

        for cluster_name in expected_clusters:
            self.assertIn(
                cluster_name,
                clusters,
                f"Cluster {cluster_name} is missing from rds.tf",
            )
            block = clusters[cluster_name]

            # CKV_AWS_327 requires kms_key_id to be configured
            self.assertTrue(
                re.search(r"kms_key_id\s*=\s*\S+", block),
                f"Resource aws_rds_cluster.{cluster_name} must have kms_key_id configured",
            )
            # Storage encryption must be enabled when specifying kms_key_id
            self.assertTrue(
                re.search(r"storage_encrypted\s*=\s*true", block),
                f"Resource aws_rds_cluster.{cluster_name} must have storage_encrypted = true",
            )

    def test_kms_key_defined_for_rds(self):
        kms_keys = extract_resources(self.content, "aws_kms_key")
        self.assertGreaterEqual(
            len(kms_keys),
            1,
            "Expected at least one aws_kms_key resource defined in rds.tf",
        )


if __name__ == "__main__":
    unittest.main()