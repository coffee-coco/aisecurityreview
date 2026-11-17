### Vulnerability Analysis
Checkov rule `CKV_ALI_4` failed on `alicloud_actiontrail_trail.fail` in `terraform/alicloud/trail.tf` because `trail_region` was set to a specific region (`"cn-hangzhou"`) instead of `"All"`.

Alibaba Cloud ActionTrail records API calls made within an account. Restricting audit logging to only a single region leaves all other regions unmonitored. An attacker operating in any region other than `cn-hangzhou` could provision, modify, or exfiltrate resources without triggering audit trails, blinding security monitoring and incident response teams.

### Remediation
In `terraform/alicloud/trail.tf`, update `trail_region` on `alicloud_actiontrail_trail.fail` to `"All"`. This ensures all management and API events across all Alibaba Cloud regions are logged to the ActionTrail destination bucket.

### Verification
- Run the provided unit test: `pytest test_actiontrail_logging_all_regions.py`.
- Run Checkov against the file: `checkov -f terraform/alicloud/trail.tf --check CKV_ALI_4`.