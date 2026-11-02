"""Deterministic static rules run across the whole codebase.

Results are aggregated per rule (one finding, many evidence locations) so the review reads as a
set of systemic issues rather than thousands of line-level alerts. Secrets are redacted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .workspace import iter_sources, language_of, read_text

CODE_LANGS = {"Python", "JavaScript", "TypeScript", "Java", "Kotlin", "Go", "Ruby", "PHP", "C#", "Rust", "Scala",
              "Swift", "Dart", "Groovy", "Elixir", "Vue", "Svelte", "C", "C++", "Shell", "PowerShell"}
JS = {"JavaScript", "TypeScript", "Vue", "Svelte"}
CONFIG_LANGS = {"YAML", "JSON", "TOML", "INI", "Config", "Properties", "Env", "XML", "Terraform", "HCL", "Dockerfile"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|docs?)/|(_test|\.test|\.spec|"
                       r"_spec)\.[a-z]+$|test_[^/]+\.py$", re.I)


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    pattern: str
    description: str
    recommendation: str
    langs: set[str] | None = None          # None = any text file
    csf: list[str] = field(default_factory=list)
    nist: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    flags: int = re.I
    skip_tests: bool = True
    secret: bool = False
    _rx: re.Pattern | None = None

    @property
    def rx(self) -> re.Pattern:
        if self._rx is None:
            self._rx = re.compile(self.pattern, self.flags)
        return self._rx


S_SECRETS = dict(category="secrets", csf=["PR.AA-01", "PR.DS-01"], nist=["IA-5", "SC-28", "SC-12"],
                 mitigations=["M-SECRETS-VAULT", "M-SECRET-SCANNING"], secret=True, skip_tests=False,
                 recommendation="Remove the secret from source, rotate it immediately, load it at runtime from a "
                                "secrets manager and enable secret scanning in the pipeline.")
S_INJ = dict(category="injection", csf=["PR.PS-06", "ID.RA-01"], nist=["SI-10", "SA-11"],
             mitigations=["M-INPUT-VALIDATION", "M-SAST-DAST"])
S_CRYPTO = dict(category="crypto", csf=["PR.DS-01", "PR.DS-02"], nist=["SC-13", "SC-12"],
                mitigations=["M-CRYPTO-STANDARDS"])
S_TLS = dict(category="transport", csf=["PR.DS-02"], nist=["SC-8", "SC-23"], mitigations=["M-TLS"])
S_AUTH = dict(category="auth", csf=["PR.AA-03", "PR.AA-05"], nist=["IA-2", "AC-3", "IA-5"],
              mitigations=["M-API-AUTH", "M-SESSION"])
S_CFG = dict(category="config", csf=["PR.PS-01"], nist=["CM-6", "CM-7"], mitigations=["M-BASELINE"])
S_AI = dict(category="ai", csf=["PR.DS-10", "PR.AA-05", "ID.RA-01"], nist=["SI-10", "AC-6", "SA-8"],
            mitigations=["M-AI-GUARDRAILS", "M-AI-TOOL-SANDBOX"])

RULES: list[Rule] = [
    # ------------------------------------------------------------------ secrets
    Rule("SEC-AWS-KEY", "AWS access key committed to source", "critical", pattern=r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
         flags=0, description="An AWS access key ID is present in the codebase.", **S_SECRETS),
    Rule("SEC-PRIVATE-KEY", "Private key committed to source", "critical",
         pattern=r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", flags=0,
         description="A private key is stored in the repository.", **S_SECRETS),
    Rule("SEC-GITHUB-TOKEN", "GitHub token committed to source", "critical",
         pattern=r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}", flags=0,
         description="A GitHub personal access / app token is present.", **S_SECRETS),
    Rule("SEC-SLACK-TOKEN", "Slack token or webhook in source", "high",
         pattern=r"\bxox[abprs]-[A-Za-z0-9-]{10,}|hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
         flags=0, description="A Slack token or incoming webhook URL is present.", **S_SECRETS),
    Rule("SEC-STRIPE-KEY", "Payment provider secret key in source", "critical",
         pattern=r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}", flags=0,
         description="A live Stripe secret/restricted key is present.", **S_SECRETS),
    Rule("SEC-GOOGLE-KEY", "Google API key in source", "high", pattern=r"\bAIza[0-9A-Za-z\-_]{35}\b", flags=0,
         description="A Google API key is present.", **S_SECRETS),
    Rule("SEC-AI-KEY", "AI provider API key in source", "critical",
         pattern=r"\bsk-(proj-|ant-)?[A-Za-z0-9_\-]{32,}", flags=0,
         description="An OpenAI / Anthropic style API key is present.", **S_SECRETS),
    Rule("SEC-JWT-LITERAL", "Hard-coded JWT", "medium",
         pattern=r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", flags=0,
         description="A literal JSON Web Token is embedded in the code.", **S_SECRETS),
    Rule("SEC-CONN-STRING", "Credentials embedded in connection string", "high",
         pattern=r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqps?|mssql|sqlserver)://[^:/\s'\"]+:[^@/\s'\"]{3,}@",
         description="A database / broker URL includes a username and password.", **S_SECRETS),
    Rule("SEC-GENERIC", "Hard-coded password or secret", "high",
         pattern=r"""(?<![A-Za-z0-9_])(password|passwd|pwd|secret|api_?key|access_?token|auth_?token|client_?secret|private_?key)\s*[:=]\s*['"][^'"\s$<>{}]{8,}['"]""",
         description="A credential-like variable is assigned a literal value.", **S_SECRETS),
    # ------------------------------------------------------------------ injection
    Rule("INJ-SQL-CONCAT", "SQL built with string concatenation / interpolation", "high",
         pattern=r"""(execute|query|raw|executemany|exec_driver_sql|createQuery|prepareStatement|db\.Exec|db\.Query)\s*\(\s*(f['"]|['"`][^'"`]*\b(select|insert|update|delete)\b[^'"`]*['"`]\s*(\+|%|\.format)|`[^`]*\b(select|insert|update|delete)\b[^`]*\$\{)""",
         langs=CODE_LANGS, description="Database queries are composed from strings that may include user input.",
         recommendation="Use parameterised queries / prepared statements or an ORM query builder; never "
                        "interpolate request data into SQL.", **S_INJ),
    Rule("INJ-SQL-TEMPLATE", "SQL statement built with string interpolation", "high",
         pattern=r"""`[^`\n]*\b(select\b[^`\n]*\bfrom|insert\s+into|update\b[^`\n]*\bset|delete\s+from)\b[^`\n]*\$\{|\bf["'][^"'\n]*\b(select\b[^"'\n]*\bfrom|insert\s+into|update\b[^"'\n]*\bset|delete\s+from)\b[^"'\n]*\{|["'][^"'\n]*\b(select\b[^"'\n]*\bfrom|insert\s+into|delete\s+from)\b[^"'\n]*["']\s*(\+|%)\s*\w""",
         langs=CODE_LANGS, description="SQL text is assembled with interpolated values and later executed.",
         recommendation="Use parameterised queries / prepared statements; pass values as bind parameters.",
         **S_INJ),
    Rule("INJ-CMD", "OS command execution with dynamic input", "high",
         pattern=r"""(subprocess\.(call|run|Popen|check_output)\([^)]*shell\s*=\s*True|os\.system\(|os\.popen\(|child_process\.exec(Sync)?\(|\bexec\(\s*[`'"][^`'"]*\$\{|Runtime\.getRuntime\(\)\.exec\(|shell_exec\(|passthru\(|\bsystem\(\s*\$)""",
         langs=CODE_LANGS, description="Commands are executed through a shell, enabling command injection if "
                                       "any argument is attacker-influenced.",
         recommendation="Avoid shell execution; pass argument arrays with shell=False and allow-list inputs.",
         **S_INJ),
    Rule("INJ-EVAL", "Dynamic code evaluation", "high",
         pattern=r"""(?<![\w.])(eval|exec)\s*\(\s*(?!['"][^'"]*['"]\s*\))|new\s+Function\s*\(|vm\.runIn(New|This)?Context\(""",
         langs=CODE_LANGS, description="eval/exec/new Function execute strings as code.",
         recommendation="Remove dynamic evaluation; use safe parsers (json.loads, ast.literal_eval) or explicit "
                        "dispatch tables.", **S_INJ),
    Rule("INJ-DESERIALISE", "Unsafe deserialisation", "high",
         pattern=r"""pickle\.loads?\(|cPickle\.loads?\(|yaml\.load\((?![^)]*SafeLoader)|yaml\.unsafe_load|marshal\.loads|jsonpickle\.decode|ObjectInputStream\(|BinaryFormatter|unserialize\(\s*\$|Marshal\.load""",
         langs=CODE_LANGS, category="deserialization", csf=["PR.PS-06"], nist=["SI-10"],
         mitigations=["M-INPUT-VALIDATION"],
         description="Deserialising untrusted data can lead to remote code execution.",
         recommendation="Use data-only formats (JSON) or safe loaders (yaml.safe_load); never unpickle untrusted "
                        "input."),
    Rule("INJ-XSS", "Unescaped HTML rendering (XSS)", "medium",
         pattern=r"""dangerouslySetInnerHTML|\.innerHTML\s*=(?!\s*['"`]\s*['"`])|\bv-html=|\|\s*safe\b|mark_safe\(|\{\{\{[^}]+\}\}\}|Html\.Raw\(|document\.write\(|bypassSecurityTrust""",
         langs=CODE_LANGS | {"HTML"}, category="xss", csf=["PR.PS-06"], nist=["SI-10", "SC-18"],
         mitigations=["M-INPUT-VALIDATION", "M-SECURITY-HEADERS"],
         description="HTML is rendered without contextual output encoding.",
         recommendation="Render via auto-escaping templates/frameworks; sanitise any required HTML with a vetted "
                        "library (e.g. DOMPurify) and deploy a strict Content-Security-Policy."),
    Rule("INJ-SSRF", "Outbound request to a user-controlled URL (SSRF)", "medium",
         pattern=r"""(requests\.(get|post|put|request)|httpx\.(get|post|AsyncClient\(\)\.get)|urllib\.request\.urlopen|fetch|axios(\.(get|post))?|http\.Get|HttpClient\(\)\.GetAsync|RestTemplate\(\)\.getForObject)\s*\(\s*(req(uest)?\.|params\[|request\.(args|json|form|query|body)|ctx\.|body\.|query\.|url\b|target\b|user_url)""",
         langs=CODE_LANGS, category="ssrf", csf=["PR.IR-01", "PR.PS-06"], nist=["SC-7", "SI-10"],
         mitigations=["M-EGRESS", "M-INPUT-VALIDATION"],
         description="The server fetches URLs derived from request data, enabling server-side request forgery "
                     "to internal services or cloud metadata.",
         recommendation="Allow-list destination hosts, block private/link-local ranges (169.254.169.254) and "
                        "route egress through a proxy."),
    Rule("INJ-PATH", "File path built from request data (path traversal)", "medium",
         pattern=r"""(open|send_file|sendFile|readFile(Sync)?|createReadStream|File\.ReadAll\w*|new\s+File|os\.path\.join|path\.join|Path\()\s*\([^)]*(request\.(args|form|files|json|query|GET|POST)|req\.(params|query|body)|params\[|filename\b)""",
         langs=CODE_LANGS, category="file_handling", csf=["PR.PS-06", "PR.DS-01"], nist=["SI-10", "AC-3"],
         mitigations=["M-INPUT-VALIDATION", "M-FILE-UPLOAD"],
         description="Filesystem paths are constructed from user input.",
         recommendation="Normalise and confine paths to an allowed base directory; use generated identifiers "
                        "instead of user-supplied filenames."),
    Rule("INJ-NOSQL", "NoSQL query built from request object", "medium",
         pattern=r"""\.(find|findOne|update\w*|delete\w*|aggregate)\(\s*(req\.(body|query|params)|request\.(json|args))""",
         langs=JS | {"Python"}, description="Request objects are passed straight into NoSQL queries "
                                             "(operator injection).",
         recommendation="Validate request schemas and cast values to expected primitive types before querying.",
         **S_INJ),
    Rule("INJ-XXE", "XML parser may resolve external entities (XXE)", "medium",
         pattern=r"""etree\.(parse|fromstring)\(|xml\.dom\.minidom\.parse|DocumentBuilderFactory\.newInstance\(\)|XMLInputFactory\.newInstance|SAXParserFactory\.newInstance|libxml_disable_entity_loader\(\s*false|resolve_entities\s*=\s*True""",
         langs=CODE_LANGS, description="XML is parsed with a library/config that may resolve external entities.",
         recommendation="Use defusedxml (Python) or disable DTDs/external entities in the parser factory.",
         **S_INJ),
    # ------------------------------------------------------------------ crypto / transport
    Rule("CRY-WEAK-HASH", "Weak hash algorithm (MD5/SHA-1)", "medium",
         pattern=r"""hashlib\.(md5|sha1)\(|createHash\(\s*['"](md5|sha1)['"]|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|\bmd5\(|sha1\(|MD5\.Create\(|SHA1\.Create\(""",
         langs=CODE_LANGS, description="MD5/SHA-1 are broken for security purposes.",
         recommendation="Use SHA-256+ for integrity, and Argon2id/bcrypt/scrypt for passwords.", **S_CRYPTO),
    Rule("CRY-WEAK-CIPHER", "Weak cipher or mode (DES/RC4/ECB)", "high",
         pattern=r"""\b(DES|3DES|TripleDES|RC4|Blowfish)\b|AES/ECB|MODE_ECB|createCipher\(""", flags=0,
         langs=CODE_LANGS, description="Obsolete ciphers or ECB mode do not provide adequate confidentiality.",
         recommendation="Use AES-GCM or ChaCha20-Poly1305 via a vetted library and managed keys (KMS).",
         **S_CRYPTO),
    Rule("CRY-INSECURE-RANDOM", "Non-cryptographic randomness for security values", "medium",
         pattern=r"""(token|secret|password|nonce|otp|session|salt|key)\w*\s*=\s*[^\n]*(Math\.random\(|random\.(random|randint|choice)\(|new\s+Random\(|rand\(\))""",
         langs=CODE_LANGS, description="Security-sensitive values are generated with a predictable PRNG.",
         recommendation="Use the platform CSPRNG (secrets, crypto.randomBytes, SecureRandom).", **S_CRYPTO),
    Rule("TLS-VERIFY-OFF", "TLS certificate verification disabled", "high",
         pattern=r"""verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|InsecureSkipVerify\s*:\s*true|CERT_NONE|ServerCertificateValidationCallback\s*=|TrustAllCerts|setHostnameVerifier\(|ssl\._create_unverified_context|curl\s[^\n]*\s(-k|--insecure)\b""",
         description="Certificate validation is disabled, allowing man-in-the-middle attacks.",
         recommendation="Always validate certificates; trust private CAs explicitly via a CA bundle.", **S_TLS),
    Rule("TLS-HTTP-URL", "Plain-text HTTP endpoint", "low",
         pattern=r"""['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|schemas\.|www\.w3\.org|example\.|json-schema|xmlns|maven\.apache|java\.sun|xml\.org|purl\.org)[a-z0-9.-]+\.[a-z]{2,}""",
         langs=CODE_LANGS | CONFIG_LANGS, description="Services are called over unencrypted HTTP.",
         recommendation="Use HTTPS (TLS 1.2+) for all external and internal service calls.", **S_TLS),
    # ------------------------------------------------------------------ auth / session
    Rule("AUTH-JWT-NONE", "JWT verification disabled or 'none' algorithm", "critical",
         pattern=r"""verify_signature['"]?\s*:\s*False|algorithms\s*=\s*\[\s*['"]none['"]|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true|\.decode\(\s*token\s*\)|algorithm\s*:\s*['"]none['"]""",
         description="JWTs are accepted without signature/expiry validation.",
         recommendation="Verify signature, issuer, audience and expiry with an explicit algorithm allow-list.",
         **S_AUTH),
    Rule("AUTH-WEAK-JWT-SECRET", "Weak / default JWT signing secret", "high",
         pattern=r"""(jwt|token)[_-]?secret\w*\s*[:=]\s*['"](secret|changeme|password|test|dev|default|mysecret|123456|your[-_]?secret[^'"]*)['"]""",
         description="JWTs are signed with a guessable secret, allowing token forgery.",
         recommendation="Use a high-entropy key from a secrets manager, or asymmetric keys (RS256/ES256).",
         **S_AUTH),
    Rule("AUTH-COOKIE-FLAGS", "Session cookie without Secure/HttpOnly", "medium",
         pattern=r"""(httponly|httpOnly|HttpOnly)\s*[:=]\s*(false|False)|(secure)\s*[:=]\s*(false|False)\b|SESSION_COOKIE_SECURE\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False""",
         flags=0, description="Session cookies can be read by scripts or sent over HTTP.",
         recommendation="Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.", **S_AUTH),
    Rule("AUTH-CSRF-OFF", "CSRF protection disabled", "medium",
         pattern=r"""csrf\(\)\.disable\(\)|@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*:\s*false|skip_before_action\s+:verify_authenticity_token""",
         description="Cross-site request forgery protection is disabled for state-changing requests.",
         recommendation="Keep CSRF protection enabled for cookie-authenticated endpoints.", **S_AUTH),
    Rule("AUTH-PERMIT-ALL", "Endpoints explicitly open to unauthenticated access", "medium",
         pattern=r"""permitAll\(\)|AllowAnonymous|@PermitAll|AllowAny\b|authorization_level\s*=\s*['"]?anonymous|auth\s*=\s*['"]?NONE['"]?|authorizationType:\s*NONE|AuthorizationType:\s*NONE""",
         description="Routes are configured to allow anonymous access; confirm each is intended to be public.",
         recommendation="Default-deny authentication; document and rate-limit the intentionally public routes.",
         **S_AUTH),
    Rule("AUTH-PLAINTEXT-PW", "Password compared or stored in plain text", "high",
         pattern=r"""(password|passwd)\s*==\s*|\.password\s*===?\s*req\.|user\.password\s*==|WHERE\s+password\s*=""",
         langs=CODE_LANGS, description="Passwords appear to be compared or queried directly rather than via a "
                                       "slow hash.",
         recommendation="Store passwords with Argon2id/bcrypt and compare using the library's verify function.",
         **S_AUTH),
    # ------------------------------------------------------------------ config / exposure
    Rule("CFG-CORS-ANY", "CORS allows any origin", "medium",
         pattern=r"""Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*|allow_origins\s*=\s*\[\s*['"]\*|origin\s*:\s*['"]\*['"]|cors\(\s*\)|AllowAnyOrigin\(\)|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allowedOrigins\(\s*"\*"\)""",
         description="Any website can call the API from a browser; with credentials this exposes user data.",
         recommendation="Allow-list exact origins; never combine wildcard origins with credentials.", **S_CFG),
    Rule("CFG-DEBUG", "Debug mode enabled", "medium",
         pattern=r"""DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True|"debug"\s*:\s*true|ASPNETCORE_ENVIRONMENT\s*[:=]\s*['"]?Development|FLASK_DEBUG\s*=\s*1|devtools\s*:\s*true""",
         description="Debug mode exposes stack traces, internals and sometimes interactive consoles.",
         recommendation="Disable debug in all deployed environments and drive it from environment config.",
         **S_CFG),
    Rule("CFG-BIND-ALL", "Service binds to all interfaces", "low",
         pattern=r"""host\s*=\s*['"]0\.0\.0\.0['"]|listen\(\s*\d+\s*,\s*['"]0\.0\.0\.0|--host[= ]0\.0\.0\.0|0\.0\.0\.0/0""",
         description="Services listen on every interface or rules allow 0.0.0.0/0.",
         recommendation="Bind to required interfaces only and restrict ingress with security groups / network "
                        "policies.", category="config", csf=["PR.IR-01"], nist=["SC-7"],
         mitigations=["M-NET-SEGMENTATION"]),
    Rule("CFG-STACKTRACE", "Errors / stack traces returned to clients", "low",
         pattern=r"""res\.(send|json)\(\s*(err|error)(\.stack)?\s*\)|traceback\.format_exc\(\)|printStackTrace\(\)|return\s+str\(e\)|detail\s*=\s*str\(e\)|\.status\(500\)\.send\(\s*err""",
         langs=CODE_LANGS, category="error_handling", csf=["PR.PS-01"], nist=["SI-11"],
         mitigations=["M-ERROR-HANDLING"],
         description="Exception details are returned to callers, leaking implementation details.",
         recommendation="Return generic error messages with a correlation ID; log details server-side."),
    Rule("CFG-LOG-SENSITIVE", "Sensitive data written to logs", "medium",
         pattern=r"""(log(ger)?|console)\.(info|debug|log|warn|error|warning)\([^)\n]*(password|passwd|secret|token|authorization|card_?number|cvv|ssn|api_?key)""",
         langs=CODE_LANGS, category="logging", csf=["PR.DS-01", "DE.CM-09"], nist=["AU-9", "SI-11"],
         mitigations=["M-LOGGING-SIEM", "M-DLP"],
         description="Secrets or personal data may be written to application logs.",
         recommendation="Redact sensitive fields with a logging filter and never log credentials or tokens."),
    Rule("CFG-FILE-UPLOAD", "File upload without visible type/size validation", "low",
         pattern=r"""multer\(|UploadFile|request\.files\[|MultipartFile|IFormFile|FileUpload\(""",
         langs=CODE_LANGS, category="file_handling", csf=["PR.PS-06"], nist=["SI-3", "SI-10"],
         mitigations=["M-FILE-UPLOAD"], description="The application accepts file uploads.",
         recommendation="Validate type by content, limit size, store outside the web root with random names and "
                        "malware-scan uploads."),
    Rule("CFG-DOCKER-ROOT", "Container runs as root / uses :latest", "low",
         pattern=r"""^FROM\s+\S+:latest\b|^FROM\s+[^:\s]+\s*$|^USER\s+root\b""", flags=re.I | re.M,
         langs={"Dockerfile"}, category="iac", csf=["PR.PS-01"], nist=["CM-6", "CM-7"],
         mitigations=["M-IMAGE-HARDENING"], skip_tests=False,
         description="Container images are unpinned or run as root.",
         recommendation="Pin base images by digest, use minimal images and run as a non-root USER."),
    Rule("CFG-CI-SECRETS", "CI pipeline uses risky triggers or prints secrets", "medium",
         pattern=r"""pull_request_target|echo\s+\$\{\{\s*secrets\.|permissions:\s*write-all|curl[^\n|]*\|\s*(ba)?sh""",
         langs={"YAML", "Groovy", "Shell"}, category="supply_chain", csf=["PR.PS-01", "GV.SC-01"],
         nist=["SA-15", "CM-5"], mitigations=["M-CICD-HARDENING"], skip_tests=False,
         description="Pipeline configuration allows untrusted code to access secrets or pipes remote scripts "
                     "to a shell.",
         recommendation="Use least-privilege tokens, avoid pull_request_target with checkout of PR code, pin "
                        "actions by SHA and never echo secrets."),
    Rule("CFG-UNPINNED-ACTION", "Third-party CI actions not pinned to a commit", "low",
         pattern=r"""uses:\s*(?!actions/|github/|\./)[\w.-]+/[\w.-]+@(v?\d+(\.\d+)*|main|master|latest)\s*$""",
         flags=re.I | re.M, langs={"YAML"}, category="supply_chain", csf=["GV.SC-01", "PR.PS-01"],
         nist=["SA-12", "SR-3"], mitigations=["M-CICD-HARDENING", "M-DEP-MGMT"], skip_tests=False,
         description="Third-party actions referenced by mutable tags can be replaced by a compromised release.",
         recommendation="Pin third-party actions to a full commit SHA and review updates via Dependabot."),
    # ------------------------------------------------------------------ AI / LLM specific
    Rule("AI-PROMPT-CONCAT", "User input concatenated into LLM prompt", "medium",
         pattern=r"""(prompt|system_prompt|messages|instructions|template)\s*[+]?=\s*(f['"]|`)[^\n]*(\{|\$\{)\s*(user_?input|query|question|message|request|req\.|body|input|text|content)""",
         langs=CODE_LANGS, description="Untrusted text is interpolated directly into prompts; prompt "
                                       "injection can override instructions.",
         recommendation="Keep system instructions separate from user content (role-separated messages), "
                        "delimit untrusted content, and apply input/output guardrails.", **S_AI),
    Rule("AI-LLM-EXEC", "LLM output executed as code or commands", "critical",
         pattern=r"""(exec|eval|subprocess\.\w+|os\.system|child_process\.exec\w*)\s*\([^)\n]*(response|completion|output|result|answer|llm|generated|message\.content|choices\[0\])""",
         langs=CODE_LANGS, description="Model output flows into code/command execution - a prompt injection "
                                       "becomes remote code execution.",
         recommendation="Never execute model output directly; use a sandbox with no credentials, strict "
                        "allow-listed tools and human approval for side-effects.", **S_AI),
    Rule("AI-LLM-SQL", "LLM output used to build database queries", "high",
         pattern=r"""(execute|query|raw)\s*\([^)\n]*(response|completion|llm_output|generated_sql|sql_query|answer)\b""",
         langs=CODE_LANGS, description="Model-generated SQL is executed against the database.",
         recommendation="Execute generated queries with a read-only, row-level-secured account and validate "
                        "them against an allow-list of tables/operations.", **S_AI),
    Rule("AI-AGENT-TOOLS", "Agent has powerful tools (shell / code / HTTP / file)", "high",
         pattern=r"""ShellTool|PythonREPLTool|PythonAstREPLTool|BashTool|TerminalTool|RequestsGetTool|RequestsPostTool|FileManagementToolkit|WriteFileTool|code_interpreter|computer_use|allow_dangerous_(code|requests)\s*=\s*True|dangerously""",
         langs=CODE_LANGS, description="The agent can invoke high-impact tools, so prompt injection could "
                                       "cause real-world actions.",
         recommendation="Restrict tools to least privilege, sandbox execution, add human-in-the-loop "
                        "approval for side-effecting actions and log every tool call.", **S_AI),
    Rule("AI-HTML-RENDER", "LLM output rendered as HTML / Markdown without sanitising", "medium",
         pattern=r"""(innerHTML|dangerouslySetInnerHTML|v-html|marked\(|markdown\()[^\n]*(response|completion|answer|message|output|content)""",
         langs=CODE_LANGS | {"HTML"}, description="Model output is rendered as markup; injected content can run "
                                                   "script or exfiltrate data via image links.",
         recommendation="Sanitise rendered output (DOMPurify), block remote images/links from model output and "
                        "apply CSP.", **S_AI),
    Rule("AI-NO-LIMITS", "LLM calls without token / cost limits", "low",
         pattern=r"""(chat\.completions\.create|messages\.create|generate_content|ChatOpenAI|ChatAnthropic)\((?![^)]*(max_tokens|max_output_tokens|maxOutputTokens))""",
         langs=CODE_LANGS, category="ai", csf=["PR.IR-04"], nist=["SC-5"], mitigations=["M-RATE-LIMIT"],
         description="Model calls do not bound output size, enabling cost/denial-of-wallet abuse.",
         recommendation="Set max tokens, per-user rate limits and spend alerts on AI provider accounts."),
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _redact(line: str) -> str:
    def mask(m: re.Match) -> str:
        s = m.group(0)
        return s[:4] + "…" + "•" * 6 if len(s) > 8 else "••••"
    line = re.sub(r"""([=:]\s?['"])([^'"]{6,})(['"])""",
                  lambda m: m.group(1) + m.group(2)[:4] + "…" + "•" * 6 + m.group(3), line)
    line = re.sub(r"\b(AKIA|ASIA|ghp_|sk-|xox[abprs]-|AIza|sk_live_|eyJ)[A-Za-z0-9_\-./+=]{6,}", mask, line)
    line = re.sub(r"(://[^:/\s]+:)[^@\s]+@", r"\1••••@", line)
    return line


def run_rules(roots: list[tuple[str, Path]], max_evidence: int = 12) -> tuple[list[dict], dict]:
    """Return (findings, stats). Deterministic: files are scanned in sorted order."""
    hits: dict[str, list[dict]] = {}
    counts: dict[str, int] = {}
    scanned = 0
    for path, p in iter_sources(roots):
        lang = language_of(path)
        text = read_text(p)
        if text is None:
            continue
        scanned += 1
        is_test = bool(TEST_PATH.search(path))
        lines = None
        for rule in RULES:
            if rule.langs is not None and lang not in rule.langs:
                continue
            if rule.skip_tests and is_test:
                continue
            for m in rule.rx.finditer(text):
                counts[rule.id] = counts.get(rule.id, 0) + 1
                ev = hits.setdefault(rule.id, [])
                if len(ev) >= max_evidence:
                    continue
                if lines is None:
                    lines = text.split("\n")
                ln = text.count("\n", 0, m.start()) + 1
                snippet = lines[ln - 1].strip()[:240]
                if rule.secret:
                    snippet = _redact(snippet)
                if not any(e["file"] == path and e["line"] == ln for e in ev):
                    ev.append({"file": path, "line": ln, "snippet": snippet})
    secret_lines = {(e["file"], e["line"]) for rid, ev in hits.items() if rid.startswith("SEC-") and
                    rid != "SEC-GENERIC" for e in ev}
    if "SEC-GENERIC" in hits:
        before = len(hits["SEC-GENERIC"])
        hits["SEC-GENERIC"] = [e for e in hits["SEC-GENERIC"] if (e["file"], e["line"]) not in secret_lines]
        counts["SEC-GENERIC"] -= before - len(hits["SEC-GENERIC"])
        if not hits["SEC-GENERIC"]:
            del hits["SEC-GENERIC"]
    findings = []
    for rule in RULES:
        if rule.id not in hits:
            continue
        n = counts[rule.id]
        files = sorted({e["file"] for e in hits[rule.id]})
        findings.append({
            "id": f"rule:{rule.id}", "rule": rule.id, "title": rule.title, "severity": rule.severity,
            "category": rule.category,
            "description": f"{rule.description} Found {n} occurrence{'s' if n != 1 else ''} across "
                           f"{len(files)}{'+' if n > len(hits[rule.id]) else ''} file{'s' if len(files) != 1 else ''}.",
            "evidence": hits[rule.id], "occurrences": n, "recommendation": rule.recommendation,
            "csf": rule.csf, "nist": rule.nist, "mitigations": rule.mitigations, "source": "rule",
        })
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["rule"]))
    return findings, {"files_scanned": scanned, "rules": len(RULES)}
