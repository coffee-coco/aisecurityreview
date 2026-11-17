# Run via: pytest test_rds_encryption.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAuroraEncryptionAtRest(unittest.TestCase):
    def test_all_rds_clusters_have_storage_encrypted(self):
        rds_tf_path = REPO_ROOT / "terraform" / "aws" / "rds.tf"
        self.assertTrue(rds_tf_path.exists(), f"{rds_tf_path} does not exist")

        content = rds_tf_path.read_text()
        cluster_matches = re.findall(
            r'resource\s+"aws_rds_cluster"\s+"([^"]+)"\s*\{(.*?)(?=\nresource|\Z)',
            content,
            re.DOTALL,
        )
        self.assertGreater(len(cluster_matches), 0, "No aws_rds_cluster resources found")

        unencrypted = []
        for name, block in cluster_matches:
            if not re.search(r'storage_encrypted\s*=\s*true', block):
                unencrypted.append(name)

        self.assertEqual(
            unencrypted,
            [],
            f"Aurora RDS cluster(s) missing storage_encrypted = true: {unencrypted}",
        )


if __name__ == "__main__":
    unittest.main()