### Vulnerability Details
Elastic Load Balancers (ELBs) accept incoming client connections and forward traffic to targets. When configured with cleartext protocols such as HTTP (`lb_protocol = "http"` on port 80), traffic between clients and the load balancer is transmitted unencrypted over the network. This exposes sensitive data, session tokens, and credentials to eavesdropping and man-in-the-middle (MitM) attacks.

### Evidence
In `terraform/aws/elb.tf` (lines 5-10):
```hcl
  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
```
The listener defines `lb_protocol = "http"` on port 80, violating Checkov check `CKV_AWS_376` ("Ensure AWS Elastic Load Balancer listener uses TLS/SSL").

### Remediation
The listener configuration was updated to use HTTPS:
- Changed `lb_port` to `443`.
- Changed `lb_protocol` to `"https"`.
- Added `ssl_certificate_id` to provide an SSL/TLS certificate ARN required for terminating TLS traffic at the ELB.

### Verification
Run the test using `pytest test_elb_tls.py` (or `python -m unittest test_elb_tls.py`). It parses `terraform/aws/elb.tf` and verifies that all listeners on `aws_elb.weblb` enforce a TLS/SSL protocol (`https` or `ssl`).