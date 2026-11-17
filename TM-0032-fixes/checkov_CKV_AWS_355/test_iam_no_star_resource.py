# Run via: pytest test_iam_no_star_resource.py
import json
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_policy_document(tf_content: str, resource_type: str, resource_name: str) -> dict:
    pattern = rf'resource\s+"{resource_type}"\s+"{resource_name}"\s*\{{.*?policy\s*=\s*<<EOF(.*?)EOF'
    match = re.search(pattern, tf_content, re.DOTALL)
    if not match:
        raise ValueError(f"Could not find policy block for {resource_type}.{resource_name}")
    return json.loads(match.group(1).strip())


class TestIAMNoStarResourceWithRestrictableActions(unittest.TestCase):
    def test_ec2policy_no_star_resource(self):
        db_app_tf = REPO_ROOT / "terraform/aws/db-app.tf"
        self.assertTrue(db_app_tf.exists(), f"{db_app_tf} does not exist")
        content = db_app_tf.read_text(encoding="utf-8")
        policy = extract_policy_document(content, "aws_iam_role_policy", "ec2policy")

        for statement in policy.get("Statement", []):
            if statement.get("Effect") == "Allow":
                resource = statement.get("Resource")
                if isinstance(resource, str):
                    resource = [resource]
                self.assertNotIn(
                    "*",
                    resource,
                    "aws_iam_role_policy.ec2policy statement must not allow '*' as resource for restrictable actions",
                )

    def test_userpolicy_no_star_resource(self):
        iam_tf = REPO_ROOT / "terraform/aws/iam.tf"
        self.assertTrue(iam_tf.exists(), f"{iam_tf} does not exist")
        content = iam_tf.read_text(encoding="utf-8")
        policy = extract_policy_document(content, "aws_iam_user_policy", "userpolicy")

        for statement in policy.get("Statement", []):
            if statement.get("Effect") == "Allow":
                resource = statement.get("Resource")
                if isinstance(resource, str):
                    resource = [resource]
                self.assertNotIn(
                    "*",
                    resource,
                    "aws_iam_user_policy.userpolicy statement must not allow '*' as resource for restrictable actions",
                )


if __name__ == "__main__":
    unittest.main()