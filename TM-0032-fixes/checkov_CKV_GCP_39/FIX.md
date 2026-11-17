### Vulnerability Explanation
Checkov rule `CKV_GCP_39` flags Google Compute Engine instances that are launched without Shielded VM enabled. Shielded VMs provide verifiable integrity for Compute Engine instances by hardening against rootkits, bootkits, and firmware-level vulnerabilities using features like Secure Boot, Virtual Trusted Platform Module (vTPM), and integrity monitoring. In `terraform/gcp/instances.tf`, the resource `google_compute_instance.server` did not define a `shielded_instance_config` block, leaving the VM without Secure Boot protection.

### Remediation
A `shielded_instance_config` block was added to `google_compute_instance.server` in `terraform/gcp/instances.tf` with the following attributes enabled:
- `enable_secure_boot = true`: Ensures firmware and bootloader verify boot software signatures.
- `enable_vtpm = true`: Enables virtual TPM for measured boot and cryptographic attestation.
- `enable_integrity_monitoring = true`: Compares runtime measurements to baseline measurements and reports integrity violations.

### Verification
The unit test `test_instances_shielded_vm.py` inspects `terraform/gcp/instances.tf`, isolates the `google_compute_instance.server` block, and validates that `shielded_instance_config` is declared with `enable_secure_boot = true`, `enable_vtpm = true`, and `enable_integrity_monitoring = true`. The test fails against the original unhardened configuration and passes once the fix is applied.