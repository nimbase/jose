# Tests for JWS compact serialization (RFC 7515 App. A, RFC 8037 A.4).
#
# (c) 2026 George Lemon | MIT License

import std/json
import std/strutils
import std/unittest

import nimcypher/algos/ecdsa

import jose/jwk
import jose/jws
import jose/algs
import jose/errors

const payloadB64 =
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" &
  "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
const payloadJson =
  "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n " &
  "\"http://example.com/is_root\":true}"

const hsKey7515 = """{"kty":"oct",
  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"""
const hsToken7515 =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." & payloadB64 &
  ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

const rsaKey7515 = """{"kty":"RSA",
  "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
  "e":"AQAB",
  "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
  "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
  "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
  "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
  "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
  "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"}"""
const rsToken7515 =
  "eyJhbGciOiJSUzI1NiJ9." & payloadB64 &
  ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" &
  "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" &
  "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" &
  "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" &
  "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" &
  "p0igcN_IoypGlUPQGe77Rw"

const es256Key7515 = """{"kty":"EC",
  "crv":"P-256",
  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"""
const es256Token7515 =
  "eyJhbGciOiJFUzI1NiJ9." & payloadB64 &
  ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" &
  "pmWQxfKTUJqPP3-Kg6NU1Q"

const es512Key7515 = """{"kty":"EC",
  "crv":"P-521",
  "x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
  "y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
  "d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"}"""
# NOTE: unlike A.1-A.3, the A.4 payload is the ASCII string "Payload".
const es512Token7515 =
  "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA." &
  "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq" &
  "wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp" &
  "EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"

const edKey8037 = """{"kty":"OKP","crv":"Ed25519",
  "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"""
const edToken8037 =
  "eyJhbGciOiJFZERTQSJ9." &
  "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc." &
  "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt" &
  "9g7sVvpAr_MuM0KAg"

const noneToken7515 =
  "eyJhbGciOiJub25lIn0." & payloadB64 & "."

suite "jws rfc7515 vectors":
  test "HS256 A.1 verifies, payload matches":
    let key = jwkFromJsonStr(hsKey7515)
    let v = jwsVerify(hsToken7515, key)
    check v.header["alg"].getStr() == "HS256"
    check v.header["typ"].getStr() == "JWT"
    check jwsVerifyStr(hsToken7515, key) == payloadJson

  test "RS256 A.2 verifies with public key":
    let priv = jwkFromJsonStr(rsaKey7515)
    check priv.hasPrivate and priv.rsaCrt
    let v = jwsVerify(rsToken7515, jwkToPublic(priv))
    check v.header["alg"].getStr() == "RS256"
    check jwsVerifyStr(rsToken7515, jwkToPublic(priv)) == payloadJson

  test "ES256 A.3 verifies with public key":
    let priv = jwkFromJsonStr(es256Key7515)
    let v = jwsVerify(es256Token7515, jwkToPublic(priv))
    check v.header["alg"].getStr() == "ES256"

  test "ES512 A.4 verifies with public key":
    let priv = jwkFromJsonStr(es512Key7515)
    let v = jwsVerify(es512Token7515, jwkToPublic(priv))
    check v.header["alg"].getStr() == "ES512"
    check jwsVerifyStr(es512Token7515, jwkToPublic(priv)) == "Payload"

  test "EdDSA RFC 8037 A.4 verifies":
    let priv = jwkFromJsonStr(edKey8037)
    let v = jwsVerify(edToken8037, jwkToPublic(priv))
    check v.header["alg"].getStr() == "EdDSA"
    check jwsVerifyStr(edToken8037, jwkToPublic(priv)) ==
      "Example of Ed25519 signing"

  test "unsecured A.5 rejected by default, accepted on opt-in":
    let key = jwkFromJsonStr(hsKey7515)
    expect(JoseError):
      discard jwsVerify(noneToken7515, key)
    let v = jwsVerify(noneToken7515, key, allowNone = true)
    check jwsVerifyStr(noneToken7515, key, allowNone = true) == payloadJson
    check v.header["alg"].getStr() == "none"

suite "jws roundtrips":
  test "HS256/384/512 sign, verify, deterministic":
    for alg in [HS256, HS384, HS512]:
      let key = jwkOctGenerate(512)
      let t1 = jwsSign(alg, key, "hello")
      let t2 = jwsSign(alg, key, "hello")
      check t1 == t2
      check jwsVerifyStr(t1, key) == "hello"

  test "RS256/384/512 + PS256/384/512 roundtrip (RFC key)":
    let priv = jwkFromJsonStr(rsaKey7515)
    for alg in [RS256, RS384, RS512, PS256, PS384, PS512]:
      let tok = jwsSign(alg, priv, "hello")
      check jwsVerifyStr(tok, jwkToPublic(priv)) == "hello"

  test "ES256/384/512 + ES256K roundtrip":
    let keys = [jwkFromJsonStr(es256Key7515), jwkEcGenerate(P384),
                jwkFromJsonStr(es512Key7515), jwkEcGenerate(Secp256k1)]
    let algs = [ES256, ES384, ES512, ES256K]
    for i in 0 ..< 4:
      let tok = jwsSign(algs[i], keys[i], "hello")
      check jwsVerifyStr(tok, jwkToPublic(keys[i])) == "hello"

  test "EdDSA roundtrip":
    let priv = jwkFromJsonStr(edKey8037)
    let tok = jwsSign(EdDSA, priv, "hello")
    check jwsVerifyStr(tok, jwkToPublic(priv)) == "hello"

  test "kid flows into header":
    var key = jwkOctGenerate(256, kid = "my-key")
    let tok = jwsSign(HS256, key, "hello")
    check jwsVerify(tok, key).header["kid"].getStr() == "my-key"

suite "jws rejection":
  test "tampered payload fails":
    let key = jwkFromJsonStr(hsKey7515)
    var bad = hsToken7515
    bad[30] = if bad[30] == 'A': 'B' else: 'A'
    expect(JoseError):
      discard jwsVerify(bad, key)

  test "tampered signature fails":
    let key = jwkFromJsonStr(hsKey7515)
    var bad = hsToken7515
    bad[^3] = if bad[^3] == 'A': 'B' else: 'A'
    expect(JoseError):
      discard jwsVerify(bad, key)

  test "wrong key fails":
    let other = jwkOctGenerate(256)
    expect(JoseError):
      discard jwsVerify(hsToken7515, other)

  test "alg/key mismatch fails":
    let oct = jwkFromJsonStr(hsKey7515)
    let rsa = jwkToPublic(jwkFromJsonStr(rsaKey7515))
    expect(JoseError):
      discard jwsSign(RS256, oct, "x")
    expect(JoseError):
      discard jwsVerify(rsToken7515, oct)
    expect(JoseError):
      discard jwsVerify(hsToken7515, rsa)

  test "ES256 with P-384 key fails":
    let key = jwkEcGenerate(P384)
    expect(JoseError):
      discard jwsSign(ES256, key, "x")

  test "private key required to sign":
    let pub = jwkToPublic(jwkFromJsonStr(rsaKey7515))
    expect(JoseError):
      discard jwsSign(RS256, pub, "x")

  test "allowAlgs restricts":
    let key = jwkFromJsonStr(hsKey7515)
    expect(JoseError):
      discard jwsVerify(hsToken7515, key, [RS256])
    check jwsVerifyStr(hsToken7515, key, [HS256]) == payloadJson

  test "crit extensions rejected (RFC 7515 App E)":
    let key = jwkEcGenerate(P256)
    let tok = jwsSign(ES256, key, "x",
                      %*{"crit": ["exp"], "exp": 1363284000})
    expect(JoseError):
      discard jwsVerify(tok, jwkToPublic(key))

  test "malformed tokens rejected":
    let key = jwkFromJsonStr(hsKey7515)
    for bad in ["", "a", "a.b", "a.b.c.d", "..", "a.b.c"]:
      expect(JoseError):
        discard jwsVerify(bad, key)

  test "d-only RSA key refuses private ops with clear error":
    let full = jwkFromJsonStr(rsaKey7515)
    let bare = jwkRsaPrivateBare(full.rsaPub.n, full.rsaPub.e, full.rsaD)
    expect(JoseError):
      discard jwsSign(RS256, bare, "x")
    # public ops still work
    check jwsVerifyStr(rsToken7515, jwkToPublic(bare)) == payloadJson
