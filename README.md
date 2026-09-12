<p align="center">
  Pure-Nim JOSE: JWS, JWE, JWK, and JWT on top of nimcypher<br>
</p>

<p align="center">
  <code>nimble install jose</code>
</p>

<p align="center">
  <a href="https://nimbase.github.io/jose/">API reference</a><br>
  <img src="https://github.com/nimbase/jose/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/nimbase/jose/workflows/docs/badge.svg" alt="Github Actions">
</p>


## Features
- JWS compact (RFC 7515): HS256/384/512, RS256/384/512, PS256/384/512,
  ES256/384/512, ES256K, EdDSA (RFC 8032 Ed25519). `alg=none` rejected
  unless explicitly opted in; `crit` headers rejected.
- JWE compact (RFC 7516): `alg` `dir`, A128KW/A192KW/A256KW,
  RSA-OAEP/RSA-OAEP-256/RSA1_5, ECDH-ES/ECDH-ES+A128KW/A192KW/A256KW
  (P-256/384/521, X25519, secp256k1), PBES2-HS256+A128KW /
  PBES2-HS384+A192KW / PBES2-HS512+A256KW; `enc` A128CBC-HS256,
  A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM, C20P.
- JWK/JWKS (RFC 7517): `oct`, `RSA`, `EC`, `OKP` (Ed25519, X25519);
  public/private parse and serialize, `kid` set lookup, RFC 7638
  thumbprints, RSA minimum 2048 bits, oct minimum 128 bits.
- JWT (RFC 7519): `JwtBuilder` for claims, `JwtChecker` for validation
  (exp/nbf with leeway, iss, aud, required claims), signed (JWS) and
  encrypted (JWE) tokens.
- Pure Nim, zero new dependencies besides nimcypher and bigints
  (`std/json` only for JSON). Errors surface as `JoseError`.
- Verified against RFC 7515/7516/7517/7518/7638/3394/8037 test vectors,
  OpenSSL, and the `jose` npm package (11/11 both directions).

## Examples
The JWE examples use this string-to-bytes helper (`jweEncrypt` and
`jwkPassword` take `openArray[byte]`):

```nim
func sb(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])
```

Signed JWT with claims validation:

```nim
import jose

let key = jwkOctGenerate(256)

var b = initJwtBuilder()
b.iss("joe")
b.sub("user-1")
b.aud("app")
b.iat(1_700_000_000)
b.exp(1_700_003_600)

let token = jwtSign(b, "HS256", key)

var c = initJwtChecker(issuer = "joe", audience = @["app"])
c.now = 1_700_000_000 # normally defaults to the current time
let claims = jwtVerify(token, key, c)
assert claims["sub"].getStr() == "user-1"
```

Raw JWS sign and verify:

```nim
import jose

let key = jwkOctGenerate(256)
let token = jwsSign("HS256", key, """{"hello":"world"}""")
assert jwsVerifyStr(token, key) == """{"hello":"world"}"""
```

JWE encrypt and decrypt (direct encryption):

```nim
import jose

let key = jwkOctGenerate(128) # 128-bit CEK for "dir" + A128GCM
let token = jweEncrypt("dir", "A128GCM", key, sb("Live long and prosper."))
assert jweDecryptStr(token, key) == "Live long and prosper."
```

Password-based JWE (PBES2):

```nim
import jose

let pw = jwkPassword(sb("correct horse battery staple"))
let token = jweEncrypt("PBES2-HS256+A128KW", "A128GCM", pw, sb("secret"))
assert jweDecryptStr(token, pw) == "secret"
```

RSA JWE with key rotation via `kid`:

```nim
import std/json
import jose

let priv = jwkFromJsonStr("""{"kty":"RSA", ... }""")
let token = jweEncrypt("RSA-OAEP", "A128GCM", priv, sb("secret"))
let set = jwksFromJson(parseJson("""{"keys":[ ... ]}"""))
assert jweDecryptStr(token, jwksFind(set, "key-id-1")) == "secret"
```

## Roadmap
- JWS/JWE JSON serializations (currently compact only).
- `zip: DEF` (deflate) content compression for JWE.
- `A*GCMKW` key management algorithms.
- X.509 (`x5c`/`x5u`) header support and JWK `use`/`key_ops` enforcement.
- Key rotation helpers and a higher-level session/claims API.

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/jose/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/jose/fork)

### 🎩 License
MIT license | Nim Community.
