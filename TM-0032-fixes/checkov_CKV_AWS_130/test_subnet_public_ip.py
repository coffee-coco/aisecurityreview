# Run with: pytest test_subnet_public_ip.py (or python -m unittest test_subnet_public_ip.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_subnet_resources(file_path):
    content = file_path.read_text()
    resources = {}
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        match = re.match(r'^\s*resource\s+(?:"aws_subnet"|aws_subnet)\s+"?([a-zA-Z0-9_-]+)"?\s*\{', line)
        if match:
            res_name = match.group(1)
            brace_count = line.count('{') - line.count('}')
            block_lines = [line]
            i += 1
            while i < len(lines) and brace_count > 0:
                cur_line = lines[i]
                brace_count += cur_line.count('{') - cur_line.count('}')
                block_lines.append(cur_line)
                i += 1
            resources[res_name] = "\n".join(block_lines)
        else:
            i += 1
    return resources


class TestSubnetPublicIpAssignment(unittest.TestCase):
    def test_ec2_subnets_do_not_assign_public_ip(self):
        ec2_file = REPO_ROOT / "terraform/aws/ec2.tf"
        self.assertTrue(ec2_file.exists(), f"{ec2_file} does not exist")
        subnets = extract_subnet_resources(ec2_file)

        for subnet_name in ["web_subnet", "web_subnet2"]:
            self.assertIn(subnet_name, subnets, f"Subnet resource {subnet_name} missing")
            block = subnets[subnet_name]
            self.assertIsNone(
                re.search(r'map_public_ip_on_launch\s*=\s*true', block, re.IGNORECASE),
                f"Subnet {subnet_name} in ec2.tf assigns public IP on launch by default (map_public_ip_on_launch = true)"
            )
            self.assertIsNotNone(
                re.search(r'map_public_ip_on_launch\s*=\s*false', block, re.IGNORECASE),
                f"Subnet {subnet_name} in ec2.tf should explicitly set map_public_ip_on_launch = false"
            )

    def test_eks_subnets_do_not_assign_public_ip(self):
        eks_file = REPO_ROOT / "terraform/aws/eks.tf"
        self.assertTrue(eks_file.exists(), f"{eks_file} does not exist")
        subnets = extract_subnet_resources(eks_file)

        for subnet_name in ["eks_subnet1", "eks_subnet2"]:
            self.assertIn(subnet_name, subnets, f"Subnet resource {subnet_name} missing")
            block = subnets[subnet_name]
            self.assertIsNone(
                re.search(r'map_public_ip_on_launch\s*=\s*true', block, re.IGNORECASE),
                f"Subnet {subnet_name} in eks.tf assigns public IP on launch by default (map_public_ip_on_launch = true)"
            )
            self.assertIsNotNone(
                re.search(r'map_public_ip_on_launch\s*=\s*false', block, re.IGNORECASE),
                f"Subnet {subnet_name} in eks.tf should explicitly set map_public_ip_on_launch = false"
            )


if __name__ == "__main__":
    unittest.main()