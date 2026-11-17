# Run with: pytest test_pipeline_security.py
import os
import pathlib
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestGitLabCIPipelineSecurity(unittest.TestCase):
    def setUp(self):
        self.config_path = REPO_ROOT / "gitlabci" / "bla.yml"

    def test_no_credential_exfiltration_or_webhook(self):
        self.assertTrue(self.config_path.exists(), f"{self.config_path} does not exist")
        content = self.config_path.read_text(encoding="utf-8")

        # Must not reference GitLab CI JWT / tokens in job scripts
        self.assertNotRegex(
            content,
            r"\$CI_JOB_JWT(_V[0-9]+)?",
            "Sensitive CI job token ($CI_JOB_JWT) is referenced in CI configuration."
        )

        # Must not transmit data to unauthenticated public webhook sites
        self.assertNotIn(
            "webhook.site",
            content,
            "Untrusted external endpoint (webhook.site) found in CI configuration."
        )


if __name__ == "__main__":
    unittest.main()