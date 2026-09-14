# Tests for JWK parsing, serialization, thumbprints (RFC 7517, RFC 7638).
#
# (c) 2026 George Lemon | MIT License

import std/json
import std/unittest

import nimcypher/algos/ecdsa

import jose/jwk
import jose/jws
import jose/algs
import jose/b64
import jose/errors

const rsaPub7517 = """{"kty":"RSA",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e": "AQAB",
  "kid": "2011-04-29"}"""

suite "jwk rfc7517":
  test "RSA public key parses, roundtrips":
    let key = jwkFromJsonStr(rsaPub7517)
    check key.kind == jwkRSA
    check key.kid == "2011-04-29"
    check not key.hasPrivate
    let rt = jwkFromJson(jwkToJson(key))
    check rt.rsaPub.n == key.rsaPub.n
    check rt.rsaPub.e == key.rsaPub.e

  test "EC P-256 public key parses (RFC 7517 3.2)":
    let key = jwkFromJsonStr(
      """{"kty":"EC","crv":"P-256","kid":"1",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}""")
    check key.kind == jwkEC
    check key.ecCurve == P256
    check not key.hasPrivate

  test "EC P-256 private key derives matching point (RFC 7517 3.3)":
    let key = jwkFromJsonStr(
      """{"kty":"EC","crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}""")
    check key.hasPrivate
    let pub = jwkToPublic(key)
    check not pub.hasPrivate
    check pub.ecPub.x == key.ecPub.x

  test "oct key parses (RFC 7517 3.1)":
    let key = jwkFromJsonStr(
      """{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}""")
    check key.kind == jwkOct
    check key.oct.len == 16

  test "Ed25519 OKP parses, seed matches pub (RFC 8037 A.4)":
    let key = jwkFromJsonStr(
      """{"kty":"OKP","crv":"Ed25519",
          "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
          "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}""")
    check key.kind == jwkOKP
    check key.hasPrivate
    check b64urlEncode(key.okpPub) ==
      "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"

suite "jwk thumbprint rfc7638":
  test "RSA SHA-256 thumbprint matches RFC 7638 3.1":
    let key = jwkFromJsonStr(rsaPub7517)
    check jwkThumbprint(key) ==
      "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

  test "private key thumbprint equals public (public members only)":
    let priv = jwkFromJsonStr(
      """{"kty":"EC","crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}""")
    let pub = jwkFromJsonStr(
      """{"kty":"EC","crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}""")
    check jwkThumbprint(priv) == jwkThumbprint(pub)

suite "jwk validation":
  test "rejects unknown kty":
    expect(JoseError):
      discard jwkFromJsonStr("""{"kty":"AKP","x":"AA"}""")

  test "rejects missing members":
    expect(JoseError):
      discard jwkFromJsonStr("""{"kty":"RSA","n":"AA"}""")

  test "rejects bad base64url":
    expect(JoseError):
      discard jwkFromJsonStr("""{"kty":"oct","k":"***"}""")

  test "rejects off-curve EC point":
    expect(JoseError):
      discard jwkFromJsonStr(
        """{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}""")

  test "rejects EC scalar/point mismatch":
    expect(JoseError):
      discard jwkFromJsonStr(
        """{"kty":"EC","crv":"P-256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "d":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"}""")

  test "rejects small RSA modulus":
    expect(JoseError):
      discard jwkFromJsonStr(
        """{"kty":"RSA","n":"AQAB","e":"AQAB"}""")

  test "rejects short oct key":
    expect(JoseError):
      discard jwkFromJsonStr("""{"kty":"oct","k":"Zg"}""")

  test "X25519 OKP parses (RFC 8037 A.6 Bob key)":
    let key = jwkFromJsonStr(
      """{"kty":"OKP","crv":"X25519","kid":"Bob",
          "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}""")
    check key.kind == jwkOKP
    check key.okpCrv == "X25519"
    check not key.hasPrivate
    check jwkThumbprint(key).len > 0

  test "EdDSA refuses X25519 keys":
    let key = jwkFromJsonStr(
      """{"kty":"OKP","crv":"X25519",
          "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}""")
    expect(JoseError):
      discard jwsSign(EdDSA, key, "x")

  test "rejects unsupported OKP curve":
    expect(JoseError):
      discard jwkFromJsonStr(
        """{"kty":"OKP","crv":"X448","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}""")

suite "jwk sets":
  test "find by kid, single-key fallback, errors":
    let a = jwkFromJsonStr(
      """{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg","kid":"a"}""")
    let b = jwkFromJsonStr(
      """{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg","kid":"b"}""")
    let set = jwksFromJson(%*{"keys": [jwkToJson(a), jwkToJson(b)]})
    check jwksFind(set, "b").kid == "b"
    check jwksFind([a], "").kid == "a"
    expect(JoseError):
      discard jwksFind(set, "")
    expect(JoseError):
      discard jwksFind(set, "zzz")
