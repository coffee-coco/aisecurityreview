# Run using: pytest test_ssh_ingress.py (from REPO_ROOT or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestSecurityGroupPort22Ingress(unittest.TestCase):
    def test_web_node_sg_does_not_allow_ssh_from_world(self):
        ec2_tf_path = REPO_ROOT / "terraform/aws/ec2.tf"
        self.assertTrue(ec2_tf_path.is_file(), f"File not found: {ec2_tf_path}")

        content = ec2_tf_path.read_text()

        # Extract the aws_security_group "web-node" resource block
        sg_match = re.search(
            r'resource\s+"aws_security_group"\s+"web-node"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(sg_match, "aws_security_group.web-node not found in ec2.tf")
        sg_block = sg_match.group(1)

        # Find all ingress blocks within the security group
        ingress_blocks = re.findall(r'ingress\s*\{(.*?)\}', sg_block, re.DOTALL)
        self.assertTrue(ingress_blocks, "No ingress blocks found in aws_security_group.web-node")

        for block in ingress_blocks:
            from_port_m = re.search(r'from_port\s*=\s*(\d+)', block)
            to_port_m = re.search(r'to_port\s*=\s*(\d+)', block)
            cidr_match = re.search(r'cidr_blocks\s*=\s*\[([^\]]*)\]', block, re.DOTALL)

            if from_port_m and to_port_m and cidr_match:
                from_port = int(from_port_m.group(1))
                to_port = int(to_port_m.group(1))
                cidr_values = re.findall(r'"([^"]+)"', cidr_match.group(1))

                # If this rule exposes port 22
                if from_port <= 22 <= to_port:
                    self.assertNotIn(
                        "0.0.0.0/0",
                        cidr_values,
                        f"Security group ingress on port 22 allows 0.0.0.0/0: {block.strip()}",
                    )

if __name__ == "__main__":
    unittest.main()