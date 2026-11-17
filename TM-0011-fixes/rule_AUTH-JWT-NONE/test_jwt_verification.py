# Run with: pytest test_jwt_verification.py (from repo root, or with REPO_ROOT set)
import unittest
import os
import pathlib
import json
import base64
import jwt

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestJWTVerificationVulnerability(unittest.TestCase):
    """Test that JWT tokens are properly verified before use."""

    def test_insecurity_decode_accepts_unverified_tokens(self):
        """Test that the vulnerable decode function accepts tokens without verification."""
        # Read the insecurity.ts file
        insecurity_path = REPO_ROOT / "lib" / "insecurity.ts"
        with open(insecurity_path, 'r') as f:
            content = f.read()

        # Check if the vulnerable pattern exists: jws.decode without verification
        # The vulnerable code is: export const decode = (token: string) => { return jws.decode(token)?.payload }
        # After fix, it should call verify() first
        
        # Look for the decode function definition
        self.assertIn("export const decode", content, "decode function should exist")
        
        # The vulnerability is that decode uses jws.decode directly without verification
        # After the fix, it should call verify() before decoding
        if "jws.decode(token)?.payload" in content and "verify(token)" not in content.split("export const decode")[1].split("\n")[0:5]:
            self.fail("Vulnerable: decode function uses jws.decode without calling verify() first")
        
        # Check that the fixed version calls verify
        decode_section = content.split("export const decode")[1].split("export const")[0]
        self.assertIn("verify(token)", decode_section, 
                     "Fixed: decode function should call verify() before decoding")

    def test_chat_getUserId_verifies_token(self):
        """Test that getUserId in chat.ts verifies tokens before decoding."""
        chat_path = REPO_ROOT / "routes" / "chat.ts"
        with open(chat_path, 'r') as f:
            content = f.read()

        # Find the getUserId function
        self.assertIn("export async function getUserId", content)
        
        # Extract the getUserId function
        getuser_section = content.split("export async function getUserId")[1].split("export async function")[0]
        
        # The vulnerable code decodes without verification:
        # const decoded = security.decode(token) as { data?: { id?: number } } | undefined
        # After fix, it should call security.verify first
        
        if "security.decode(token)" in getuser_section and "security.verify(token)" not in getuser_section:
            self.fail("Vulnerable: getUserId decodes token without verification")
        
        # Check that verification is present
        self.assertIn("security.verify(token)", getuser_section,
                     "Fixed: getUserId should verify token before decoding")

    def test_chat_tool_call_handler_verifies_token(self):
        """Test that the tool-call handler in chat.ts verifies tokens."""
        chat_path = REPO_ROOT / "routes" / "chat.ts"
        with open(chat_path, 'r') as f:
            content = f.read()

        # Find the tool-call case in the event handler
        self.assertIn("case 'tool-call':", content)
        
        # Extract the tool-call section
        toolcall_section = content.split("case 'tool-call':")[1].split("case '")[0]
        
        # The vulnerable code at line 223:
        # const decoded = token ? security.decode(token) as { data?: { role?: string } } : undefined
        # After fix, should verify first
        
        if "security.decode(token)" in toolcall_section and "security.verify(token)" not in toolcall_section:
            self.fail("Vulnerable: tool-call handler decodes token without verification")
        
        # Check that verification is present
        self.assertIn("security.verify(token)", toolcall_section,
                     "Fixed: tool-call handler should verify token before decoding")

    def test_verify_jwtChallenge_checks_decode_before_verify(self):
        """Test that jwtChallenge in verify.ts properly checks token structure."""
        verify_path = REPO_ROOT / "routes" / "verify.ts"
        with open(verify_path, 'r') as f:
            content = f.read()

        # Find the jwtChallenge function
        self.assertIn("function jwtChallenge", content)
        
        # Extract the jwtChallenge function
        jwtchallenge_section = content.split("function jwtChallenge")[1].split("function ")[0]
        
        # The vulnerable code at line 119:
        # const decoded = jws.decode(token) ? jwt.decode(token) : null
        # This decodes without verification. After fix, should check structure safely.
        
        # The fix should check if jws.decode succeeds before calling jwt.decode
        if "jws.decode(token) ? jwt.decode(token)" in jwtchallenge_section:
            self.fail("Vulnerable: jwtChallenge uses conditional decode without proper verification")
        
        # Check that the pattern is fixed (should check decode result properly)
        self.assertIn("jws.decode(token)", jwtchallenge_section,
                     "jwtChallenge should still check token structure")
        self.assertIn("jwt.decode(token)", jwtchallenge_section,
                     "jwtChallenge should decode after structure check")

if __name__ == '__main__':
    unittest.main()