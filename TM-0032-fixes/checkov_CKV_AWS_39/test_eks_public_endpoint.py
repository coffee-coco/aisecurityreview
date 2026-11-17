# Run with: pytest test_eks_public_endpoint.py (from REPO_ROOT)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestEKSPublicEndpointDisabled(unittest.TestCase):
    def test_eks_public_endpoint_disabled(self):
        eks_tf = REPO_ROOT / "terraform/aws/eks.tf"
        self.assertTrue(eks_tf.is_file(), f"{eks_tf} does not exist")
        content = eks_tf.read_text()

        # Locate aws_eks_cluster resource block
        match = re.search(r'resource\s+"?aws_eks_cluster"?\s+"?eks_cluster"?\s*\{', content)
        self.assertIsNotNone(match, "aws_eks_cluster.eks_cluster resource not found")
        start_pos = match.end() - 1

        # Parse resource block matching braces
        depth = 0
        end_pos = -1
        for i in range(start_pos, len(content)):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
                if depth == 0:
                    end_pos = i
                    break
        self.assertNotEqual(end_pos, -1, "Could not parse aws_eks_cluster block")
        cluster_block = content[start_pos:end_pos]

        # Locate vpc_config block within aws_eks_cluster
        vpc_match = re.search(r'vpc_config\s*\{', cluster_block)
        self.assertIsNotNone(vpc_match, "vpc_config block not found in aws_eks_cluster")
        vpc_start = vpc_match.end() - 1
        depth = 0
        vpc_end = -1
        for i in range(vpc_start, len(cluster_block)):
            if cluster_block[i] == '{':
                depth += 1
            elif cluster_block[i] == '}':
                depth -= 1
                if depth == 0:
                    vpc_end = i
                    break
        self.assertNotEqual(vpc_end, -1, "Could not parse vpc_config block")
        vpc_block = cluster_block[vpc_start:vpc_end]

        # Check that endpoint_public_access is explicitly set to false (CKV_AWS_39)
        self.assertTrue(
            bool(re.search(r'\bendpoint_public_access\s*=\s*false\b', vpc_block)),
            "EKS cluster public endpoint is not disabled (endpoint_public_access = false missing in vpc_config)",
        )


if __name__ == "__main__":
    unittest.main()