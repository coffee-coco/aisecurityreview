# Run with: pytest test_elb_tls.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestELBListenerTLS(unittest.TestCase):
    def test_elb_listener_uses_tls_ssl(self):
        elb_path = REPO_ROOT / "terraform/aws/elb.tf"
        self.assertTrue(elb_path.exists(), f"File {elb_path} does not exist")

        content = elb_path.read_text()

        # Find the aws_elb resource block for weblb
        elb_match = re.search(
            r'resource\s+"aws_elb"\s+"weblb"\s+\{(.*?\n)\}', content, re.DOTALL
        )
        self.assertIsNotNone(elb_match, "aws_elb.weblb resource block not found")
        elb_body = elb_match.group(1)

        # Extract all listener blocks
        listener_matches = re.findall(
            r'listener\s+\{(.*?)\}', elb_body, re.DOTALL
        )
        self.assertTrue(
            len(listener_matches) > 0, "No listener blocks found in aws_elb.weblb"
        )

        for listener in listener_matches:
            protocol_match = re.search(r'lb_protocol\s*=\s*"([^"]+)"', listener)
            self.assertIsNotNone(
                protocol_match, "lb_protocol not specified in listener block"
            )
            protocol = protocol_match.group(1).lower()
            self.assertIn(
                protocol,
                ["https", "ssl"],
                f"ELB listener protocol should use TLS/SSL ('https' or 'ssl'), found: '{protocol}'",
            )


if __name__ == "__main__":
    unittest.main()