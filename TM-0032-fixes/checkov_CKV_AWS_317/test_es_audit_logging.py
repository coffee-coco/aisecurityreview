# Run with: pytest test_es_audit_logging.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_block(content: str, header_pattern: str) -> str:
    match = re.search(header_pattern, content)
    if not match:
        return ""
    open_brace_idx = content.find("{", match.end() - 1)
    if open_brace_idx == -1:
        return ""
    depth = 1
    i = open_brace_idx + 1
    while i < len(content) and depth > 0:
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
        i += 1
    return content[open_brace_idx + 1 : i - 1]


class TestElasticsearchAuditLogging(unittest.TestCase):
    def test_audit_logging_enabled(self):
        target_file = REPO_ROOT / "terraform/aws/es.tf"
        self.assertTrue(target_file.exists(), f"Expected file {target_file} to exist")
        content = target_file.read_text(encoding="utf-8")

        domain_block = extract_block(
            content,
            r'resource\s+"aws_elasticsearch_domain"\s+"monitoring-framework"\s*\{',
        )
        self.assertTrue(
            domain_block,
            "Could not find aws_elasticsearch_domain.monitoring-framework block in es.tf",
        )

        log_block = extract_block(domain_block, r'log_publishing_options\s*\{')
        self.assertTrue(
            log_block,
            "aws_elasticsearch_domain.monitoring-framework is missing a log_publishing_options block",
        )

        self.assertTrue(
            re.search(r'log_type\s*=\s*"AUDIT_LOGS"', log_block),
            "log_publishing_options must have log_type set to 'AUDIT_LOGS'",
        )
        self.assertTrue(
            re.search(r'enabled\s*=\s*true', log_block),
            "log_publishing_options must have enabled = true",
        )


if __name__ == "__main__":
    unittest.main()