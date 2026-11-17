# Run via `pytest test_security_group_egress.py` or `python -m unittest test_security_group_egress.py` from repository root
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestSecurityGroupEgressRule(unittest.TestCase):
    def test_db_app_egress_rule_does_not_allow_all_traffic_to_world(self):
        db_app_path = REPO_ROOT / "terraform/aws/db-app.tf"
        self.assertTrue(db_app_path.exists(), f"{db_app_path} does not exist")
        content = db_app_path.read_text()

        # Extract aws_security_group_rule.egress resource block
        match = re.search(
            r'resource\s+"aws_security_group_rule"\s+"egress"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "aws_security_group_rule.egress block not found")
        block = match.group(1)

        is_all_ports = (
            re.search(r'protocol\s*=\s*"-1"', block)
            or re.search(r'from_port\s*=\s*0\s+to_port\s*=\s*0', block)
            or re.search(r'from_port\s*=\s*-1', block)
        )
        has_open_egress = '"0.0.0.0/0"' in block

        self.assertFalse(
            is_all_ports and has_open_egress,
            "aws_security_group_rule.egress allows egress to 0.0.0.0/0 on port -1 / all protocols",
        )

    def test_ec2_web_node_egress_does_not_allow_all_traffic_to_world(self):
        ec2_path = REPO_ROOT / "terraform/aws/ec2.tf"
        self.assertTrue(ec2_path.exists(), f"{ec2_path} does not exist")
        content = ec2_path.read_text()

        # Extract aws_security_group.web-node resource block
        sg_match = re.search(
            r'resource\s+"aws_security_group"\s+"web-node"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(sg_match, "aws_security_group.web-node block not found")
        sg_block = sg_match.group(1)

        # Extract egress block inside aws_security_group.web-node
        egress_match = re.search(r'egress\s*\{(.*?)\}', sg_block, re.DOTALL)
        self.assertIsNotNone(egress_match, "egress block in aws_security_group.web-node not found")
        egress_block = egress_match.group(1)

        is_all_ports = (
            re.search(r'protocol\s*=\s*"-1"', egress_block)
            or re.search(r'from_port\s*=\s*0\s+to_port\s*=\s*0', egress_block)
            or re.search(r'from_port\s*=\s*-1', egress_block)
        )
        has_open_egress = '"0.0.0.0/0"' in egress_block

        self.assertFalse(
            is_all_ports and has_open_egress,
            "aws_security_group.web-node egress allows egress to 0.0.0.0/0 on port -1 / all protocols",
        )


if __name__ == "__main__":
    unittest.main()