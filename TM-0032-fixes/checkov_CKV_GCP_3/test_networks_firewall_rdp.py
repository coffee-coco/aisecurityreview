# Run with: pytest test_networks_firewall_rdp.py (from repo root or set REPO_ROOT)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestGoogleComputeFirewallRdp(unittest.TestCase):
    def test_allow_all_firewall_does_not_permit_unrestricted_rdp(self):
        target_file = REPO_ROOT / "terraform/gcp/networks.tf"
        self.assertTrue(target_file.is_file(), f"Target file {target_file} not found")
        content = target_file.read_text()

        firewall_match = re.search(
            r'resource\s+"google_compute_firewall"\s+"allow_all"\s*{(.*?)\n}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            firewall_match,
            "Could not find resource 'google_compute_firewall.allow_all' in networks.tf",
        )
        firewall_block = firewall_match.group(1)

        source_ranges_match = re.search(
            r'source_ranges\s*=\s*\[(.*?)\]',
            firewall_block,
            re.DOTALL,
        )
        self.assertIsNotNone(
            source_ranges_match,
            "Attribute 'source_ranges' not found in google_compute_firewall.allow_all",
        )

        raw_ranges = source_ranges_match.group(1)
        parsed_ranges = [
            r.strip().strip('"\'')
            for r in raw_ranges.split(",")
            if r.strip().strip('"\'')
        ]

        unrestricted_cidrs = {"0.0.0.0/0", "::/0"}
        overlapping_cidrs = set(parsed_ranges).intersection(unrestricted_cidrs)

        self.assertFalse(
            bool(overlapping_cidrs),
            f"google_compute_firewall.allow_all allows unrestricted ingress from {overlapping_cidrs}, exposing RDP (port 3389).",
        )


if __name__ == "__main__":
    unittest.main()