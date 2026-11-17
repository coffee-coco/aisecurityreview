### Vulnerability Details
In `packages/sub/pom.xml`, the property `<log4j.version>` was set to `2.14.0`. This version of `org.apache.logging.log4j:log4j-core` is vulnerable to CVE-2021-44228 and CVE-2021-45046 (commonly known as Log4Shell). When message lookup substitution evaluates untrusted input containing JNDI lookup strings (such as `${jndi:ldap://...}`), Log4j resolves the lookup over the network, allowing remote attackers to achieve unauthenticated arbitrary code execution.

### Fix Details
The `<log4j.version>` property in `packages/sub/pom.xml` was upgraded from `2.14.0` to `2.17.1`. In version 2.17.1, JNDI lookup support is disabled by default and message lookup evaluation is removed, remediating the vulnerability.

### Verification
The included test (`test_pom_log4j_version.py`) parses `packages/sub/pom.xml` and asserts that `log4j.version` is at least version `2.17.1`. It fails against the vulnerable version `2.14.0` and passes with `2.17.1`.