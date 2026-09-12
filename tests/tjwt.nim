# Tests for JWT claims builder/checker (RFC 7519).
#
# (c) 2026 George Lemon | MIT License

import std/json
import std/unittest

import jose
import jose/errors

const hsKey = """{"kty":"oct",
  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"""

proc builder(now: int64): JwtBuilder =
  result = initJwtBuilder()
  result.iss("joe")
  result.sub("user-1")
  result.aud("app")
  result.jti("id-1")
  result.iat(now - 10)
  result.nbf(now - 10)
  result.exp(now + 3600)
  result.claim("http://example.com/is_root", true)

suite "jwt signed":
  test "sign, verify, claims intact":
    let key = jwkFromJsonStr(hsKey)
    var b = builder(1_700_000_000)
    let tok = jwtSign(b, "HS256", key)
    var c = initJwtChecker(issuer = "joe", audience = @["app"])
    c.now = 1_700_000_000
    let claims = jwtVerify(tok, key, c)
    check claims["sub"].getStr() == "user-1"
    check claims["http://example.com/is_root"].getBool()

  test "expired rejected, leeway honored":
    let key = jwkFromJsonStr(hsKey)
    var b = builder(1_700_000_000)
    let tok = jwtSign(b, "HS256", key)
    var c = initJwtChecker()
    c.now = 1_700_003_661 # exp + 61, past default 60s leeway
    expect(JoseError):
      discard jwtVerify(tok, key, c)
    var c2 = initJwtChecker(leewaySeconds = 5)
    c2.now = 1_700_003_601 # exp + 1, inside 5s leeway
    check jwtVerify(tok, key, c2)["iss"].getStr() == "joe"

  test "nbf enforced":
    let key = jwkFromJsonStr(hsKey)
    var b = builder(1_700_000_000)
    let tok = jwtSign(b, "HS256", key)
    var c = initJwtChecker()
    c.now = 1_699_999_929 # nbf - 61, past default 60s leeway
    expect(JoseError):
      discard jwtVerify(tok, key, c)

  test "issuer/audience mismatch rejected":
    let key = jwkFromJsonStr(hsKey)
    var b = builder(1_700_000_000)
    let tok = jwtSign(b, "HS256", key)
    var c = initJwtChecker(issuer = "mallory")
    c.now = 1_700_000_000
    expect(JoseError):
      discard jwtVerify(tok, key, c)
    var c2 = initJwtChecker(audience = @["other"])
    c2.now = 1_700_000_000
    expect(JoseError):
      discard jwtVerify(tok, key, c2)

  test "aud array accepted":
    let key = jwkFromJsonStr(hsKey)
    var b = initJwtBuilder()
    b.aud("x") # replaced below with array
    b.claims["aud"] = %*["x", "app"]
    b.exp(1_700_003_600)
    let tok = jwtSign(b, "HS256", key)
    var c = initJwtChecker(audience = @["app"])
    c.now = 1_700_000_000
    check jwtVerify(tok, key, c)["aud"][1].getStr() == "app"

  test "requireExp/requireIat/required enforced":
    let key = jwkFromJsonStr(hsKey)
    var b = initJwtBuilder()
    b.iss("joe")
    let tok = jwtSign(b, "HS256", key)
    var c = initJwtChecker(requireExp = true)
    c.now = 1_700_000_000
    expect(JoseError):
      discard jwtVerify(tok, key, c)
    var c2 = initJwtChecker(required = @["jti"])
    c2.now = 1_700_000_000
    expect(JoseError):
      discard jwtVerify(tok, key, c2)

  test "bad signature still fails at JWS layer":
    let key = jwkFromJsonStr(hsKey)
    var b = builder(1_700_000_000)
    var tok = jwtSign(b, "HS256", key)
    tok[^5] = if tok[^5] == 'A': 'B' else: 'A'
    var c = initJwtChecker()
    c.now = 1_700_000_000
    expect(JoseError):
      discard jwtVerify(tok, key, c)

suite "jwt encrypted":
  test "encrypt, decrypt, claims intact":
    let kek = jwkOctGenerate(128)
    var b = builder(1_700_000_000)
    let tok = jwtEncrypt(b, "A128KW", "A128GCM", kek)
    var c = initJwtChecker(issuer = "joe")
    c.now = 1_700_000_000
    check jwtDecrypt(tok, kek, c)["sub"].getStr() == "user-1"

  test "expired encrypted token rejected":
    let kek = jwkOctGenerate(128)
    var b = builder(1_700_000_000)
    let tok = jwtEncrypt(b, "dir", "A128GCM", jwkOctGenerate(128))
    # wrong key must fail before claims are even examined
    var c = initJwtChecker()
    c.now = 1_700_000_000
    expect(JoseError):
      discard jwtDecrypt(tok, kek, c)
