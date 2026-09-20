# Tests for base64url (RFC 7515 section 2).
#
# (c) 2026 George Lemon | MIT License

import std/unittest

import ../src/jose/b64
import ../src/jose/errors

suite "b64url":
  test "RFC 7515 appendix A.1 protected header segment":
    # {"typ":"JWT","alg":"HS256"} -> eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
    check b64urlEncode("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}") ==
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"

  test "url-safe alphabet, no padding":
    check b64urlEncode([byte(0xFB), byte(0xFF), byte(0xFE)]) == "-__-"
    check b64urlEncode("f") == "Zg"
    check b64urlEncode("fo") == "Zm8"
    check b64urlEncode("foo") == "Zm9v"

  test "roundtrip incl. empty and binary":
    check b64urlDecode("") == newSeq[byte]()
    let data = [byte(0), byte(1), byte(127), byte(128), byte(255)]
    check b64urlDecode(b64urlEncode(data)) == @data

  test "decode rejects bad input":
    expect(JoseError):
      discard b64urlDecode("ab+c")
    expect(JoseError):
      discard b64urlDecode("abc=d")
    expect(JoseError):
      discard b64urlDecode("a") # mod-4 == 1 is impossible

  test "base64urlUInt strips leading zeros, zero is single octet":
    check b64urlEncodeInt([byte(0), byte(0), byte(1), byte(2)]) ==
      b64urlEncode([byte(1), byte(2)])
    check b64urlEncodeInt([byte(0), byte(0)]) == "AA"
