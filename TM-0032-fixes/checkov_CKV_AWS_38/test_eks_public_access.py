# Run with: pytest test_eks_public_access.py from repo root (or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestEKSPublicAccess(unittest.TestCase):
    def test_eks_public_endpoint_disabled_or_restricted(self):
        eks_file = REPO_ROOT / "terraform/aws/eks.tf"
        self.assertTrue(eks_file.exists(), f"{eks_file} does not exist")
        content = eks_file.read_text()

        cluster_match = re.search(
            r'resource\s+"aws_eks_cluster"\s+"eks_cluster"\s*\{(?P<body>[\s\S]*?\n\})',
            content,
        )
        self.assertIsNotNone(cluster_match, "aws_eks_cluster.eks_cluster resource not found")
        cluster_body = cluster_match.group("body")

        vpc_config_match = re.search(r'vpc_config\s*\{(?P<vpc_body>[\s\S]*?)\}', cluster_body)
        self.assertIsNotNone(vpc_config_match, "vpc_config block not found in eks_cluster")
        vpc_body = vpc_config_match.group("vpc_body")

        public_access_false = bool(
            re.search(r'endpoint_public_access\s*=\s*false', vpc_body, re.IGNORECASE)
        )

        cidrs_match = re.search(r'public_access_cidrs\s*=\s*\[([^\]]*)\]', vpc_body)
        cidrs_restricted = False
        if cidrs_match:
            cidrs = [c.strip().strip('"').strip("'") for c in cidrs_match.group(1).split(",") if c.strip()]
            if cidrs and "0.0.0.0/0" not in cidrs:
                cidrs_restricted = True

        self.assertTrue(
            public_access_false or cidrs_restricted,
            "Amazon EKS cluster endpoint public access is not disabled (endpoint_public_access = false) "
            "nor restricted to specific CIDRs excluding 0.0.0.0/0.",
        )

if __name__ == "__main__":
    unittest.main()