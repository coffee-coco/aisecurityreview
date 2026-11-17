## Vulnerability

The application accepts and processes JWT tokens without proper signature verification in multiple locations. Specifically:

1. **lib/insecurity.ts line 56**: The `decode()` function uses `jws.decode(token)?.payload` which extracts the payload without verifying the signature. This allows attackers to forge tokens with arbitrary claims.

2. **routes/chat.ts lines 45 & 223**: Both `getUserId()` and the tool-call handler call `security.decode()` directly without first calling `security.verify()`, accepting unverified tokens.

3. **routes/verify.ts line 119**: The `jwtChallenge()` function uses a pattern `jws.decode(token) ? jwt.decode(token) : null` that decodes tokens without verification.

## Why It's Exploitable

JWT tokens consist of three parts: header, payload, and signature. The `jws.decode()` and `jwt.decode()` functions only parse and base64-decode the token structure—they do NOT verify the cryptographic signature. An attacker can:

1. Create a token with arbitrary claims (e.g., `{"data": {"id": 1, "role": "admin"}}`)
2. Base64-encode it without a valid signature (or use algorithm "none")
3. Send it to the application
4. The application accepts it as valid and grants unauthorized access

This violates NIST IA-2 (identification and authentication), AC-3 (access enforcement), and IA-5 (authenticator management).

## The Fix

### lib/insecurity.ts
Changed the `decode()` function to:
1. First call `verify(token)` to check the signature
2. Only if verification succeeds, use `jwt.verify()` with explicit algorithm allowlist (`algorithms: ['RS256']`)
3. Return `undefined` if verification fails

This ensures tokens are cryptographically validated before any claims are trusted.

### routes/chat.ts
Added `security.verify(token)` checks before calling `security.decode()` in:
1. `getUserId()` function (line 44-45)
2. Tool-call handler in the chat event loop (line 222-223)

Both now return early if verification fails, preventing unverified tokens from being processed.

### routes/verify.ts
Changed the `jwtChallenge()` function to:
1. Check if `jws.decode(token)` succeeds (structure check)
2. Call `jwt.decode(token)` separately (not in a ternary)
3. The subsequent `jwt.verify()` call (line 125) already validates the signature

This maintains the challenge logic while ensuring proper validation flow.

## Verification

Run the test with:
```bash
pytest test_jwt_verification.py
```

The test:
1. Reads each affected file from disk
2. Checks for the vulnerable patterns (decode without verify)
3. Asserts that verification calls are present before decoding
4. **Fails on vulnerable code** (missing verify calls)
5. **Passes on fixed code** (verify before decode)

You can also manually test by:
1. Creating a forged JWT with `{"alg":"none"}` header
2. Sending it to endpoints like `/rest/user/whoami` or the chat API
3. Vulnerable code accepts it; fixed code rejects it with 401/403