# Run with: pytest test_security_group_port_80.py (or python -m unittest test_security_group_port_80.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def _extract_hcl_block(content: str, prefix: str) -> str | None:
    start_idx = content.find(prefix)
    if start_idx == -1:
        return None
    open_brace_idx = content.find("{", start_idx)
    if open_brace_idx == -1:
        return None
    depth = 0
    for i in range(open_brace_idx, len(content)):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return content[open_brace_idx + 1 : i]
    return None


class TestSecurityGroupPort80(unittest.TestCase):
    def test_no_ingress_from_0_0_0_0_to_port_80(self):
        ec2_tf_path = REPO_ROOT / "terraform" / "aws" / "ec2.tf"
        self.assertTrue(ec2_tf_path.is_file(), f"File not found: {ec2_tf_path}")
        content = ec2_tf_path.read_text()

        sg_block = _extract_hcl_block(content, 'resource "aws_security_group" "web-node"')
        self.assertIsNotNone(sg_block, 'aws_security_group "web-node" block not found in ec2.tf')

        # Find all ingress blocks within the security group
        ingress_starts = [m.start() for m in re.finditer(r'\bingress\b', sg_block)]
        self.assertTrue(len(ingress_starts) > 0, "No ingress blocks found in web-node")

        for start in ingress_starts:
            ingress_content = _extract_hcl_block(sg_block[start:], "ingress")
            if not ingress_content:
                continue

            from_port_match = re.search(r'from_port\s*=\s*(\d+)', ingress_content)
            to_port_match = re.search(r'to_port\s*=\s*(\d+)', ingress_content)

            if from_port_match and to_port_match:
                from_port = int(from_port_match.group(1))
                to_port = int(to_port_match.group(1))

                if from_port <= 80 <= to_port:
                    self.assertNotIn(
                        "0.0.0.0/0",
                        ingress_content,
                        "aws_security_group.web-node allows ingress from 0.0.0.0/0 to port 80 (CKV_AWS_260)",
                    )


if __name__ == "__main__":
    unittest.main()