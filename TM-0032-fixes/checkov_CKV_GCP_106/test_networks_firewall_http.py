# Run with: pytest test_networks_firewall_http.py (from repository root, or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestGoogleComputeFirewallHTTP(unittest.TestCase):
    def test_allow_all_firewall_does_not_permit_unrestricted_port_80(self):
        networks_tf_path = REPO_ROOT / "terraform" / "gcp" / "networks.tf"
        self.assertTrue(
            networks_tf_path.is_file(),
            f"Expected networks.tf to exist at {networks_tf_path}",
        )
        content = networks_tf_path.read_text()

        # Locate resource "google_compute_firewall" "allow_all" block
        match = re.search(
            r'resource\s+"google_compute_firewall"\s+"allow_all"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            match, "Resource google_compute_firewall.allow_all not found in networks.tf"
        )
        block = match.group(1)

        # Extract source_ranges
        source_ranges_match = re.search(r'source_ranges\s*=\s*\[([^\]]*)\]', block)
        self.assertIsNotNone(
            source_ranges_match,
            "source_ranges not found in google_compute_firewall.allow_all",
        )
        source_ranges = [
            s.strip().strip('"\'')
            for s in source_ranges_match.group(1).split(",")
            if s.strip()
        ]

        # Extract allowed ports
        ports_match = re.search(r'ports\s*=\s*\[([^\]]*)\]', block)
        ports = []
        if ports_match:
            ports = [
                p.strip().strip('"\'')
                for p in ports_match.group(1).split(",")
                if p.strip()
            ]

        def port_range_includes_80(port_spec: str) -> bool:
            if "-" in port_spec:
                start, end = port_spec.split("-", 1)
                return int(start) <= 80 <= int(end)
            return int(port_spec) == 80

        allows_port_80 = any(port_range_includes_80(p) for p in ports)
        has_unrestricted_cidr = any(cidr in {"0.0.0.0/0", "::/0"} for cidr in source_ranges)

        # Unrestricted ingress to port 80 must not be permitted
        self.assertFalse(
            has_unrestricted_cidr and allows_port_80,
            "google_compute_firewall.allow_all allows unrestricted ingress (0.0.0.0/0) to HTTP port 80",
        )


if __name__ == "__main__":
    unittest.main()