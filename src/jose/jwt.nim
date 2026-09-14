# JSON Web Token (JWT, RFC 7519): claims builder/checker over JWS/JWE.
#
# (c) 2026 George Lemon | MIT License

import std/json
import std/times

import ./errors
import ./algs
import ./jwk
import ./jws
import ./jwe

type
  JwtBuilder* = object
    ## Incrementally built JWT claims set.
    claims*: JsonNode

  JwtChecker* = object
    ## Validation policy for inbound JWT claims.
    leewaySeconds*: int64
      ## Clock-skew tolerance for exp/nbf (default 60).
    issuer*: string
      ## Required `iss` value (empty = not checked).
    audience*: seq[string]
      ## Acceptable `aud` values (empty = not checked).
    requireExp*: bool
      ## Reject tokens without `exp` (default false).
    requireIat*: bool
      ## Reject tokens without `iat` (default false).
    required*: seq[string]
      ## Additional claim names that must be present.
    now*: int64
      ## Reference time as Unix seconds (0 = current time).

proc sb(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

proc payloadStr(data: openArray[byte]): string =
  result = newString(data.len)
  for i in 0 ..< data.len: result[i] = char(data[i])

proc initJwtBuilder*(): JwtBuilder =
  JwtBuilder(claims: newJObject())

proc claim*(b: var JwtBuilder, name: string, value: JsonNode) =
  ## Set a claim to an arbitrary JSON value.
  b.claims[name] = value

proc claim*(b: var JwtBuilder, name, value: string) =
  b.claims[name] = %value

proc claim*(b: var JwtBuilder, name: string, value: int64) =
  b.claims[name] = %value

proc claim*(b: var JwtBuilder, name: string, value: bool) =
  b.claims[name] = %value

proc iss*(b: var JwtBuilder, v: string) = b.claim("iss", v)
proc sub*(b: var JwtBuilder, v: string) = b.claim("sub", v)
proc aud*(b: var JwtBuilder, v: string) = b.claim("aud", v)
proc jti*(b: var JwtBuilder, v: string) = b.claim("jti", v)
proc exp*(b: var JwtBuilder, v: int64) = b.claim("exp", v)
proc nbf*(b: var JwtBuilder, v: int64) = b.claim("nbf", v)
proc iat*(b: var JwtBuilder, v: int64) = b.claim("iat", v)

proc initJwtChecker*(leewaySeconds = 60'i64, issuer = "",
                     audience: seq[string] = @[],
                     requireExp = false, requireIat = false,
                     required: seq[string] = @[]): JwtChecker =
  JwtChecker(leewaySeconds: leewaySeconds, issuer: issuer,
             audience: audience, requireExp: requireExp,
             requireIat: requireIat, required: required, now: 0)

proc refTime(c: JwtChecker): int64 =
  if c.now != 0: c.now else: getTime().toUnix()

proc numClaim(claims: JsonNode, name: string): int64 =
  let v = claims[name]
  if v.kind != JInt:
    joseFail("JWT claim must be a number: " & name)
  v.getInt()

proc checkClaims*(c: JwtChecker, claims: JsonNode): JsonNode =
  ## Validate `claims` against the policy, returning them unchanged.
  ## Raises JoseError on any violation.
  if claims.kind != JObject:
    joseFail("JWT claims must be a JSON object")
  let now = c.refTime()
  if c.requireExp and not claims.hasKey("exp"):
    joseFail("JWT missing required exp claim")
  if c.requireIat and not claims.hasKey("iat"):
    joseFail("JWT missing required iat claim")
  for name in c.required:
    if not claims.hasKey(name):
      joseFail("JWT missing required claim: " & name)
  if claims.hasKey("exp"):
    if numClaim(claims, "exp") < now - c.leewaySeconds:
      joseFail("JWT has expired")
  if claims.hasKey("nbf"):
    if numClaim(claims, "nbf") > now + c.leewaySeconds:
      joseFail("JWT not yet valid")
  if c.issuer.len > 0:
    if not claims.hasKey("iss") or claims["iss"].kind != JString or
        claims["iss"].getStr() != c.issuer:
      joseFail("JWT issuer mismatch")
  if c.audience.len > 0:
    if not claims.hasKey("aud"):
      joseFail("JWT audience mismatch")
    let aud = claims["aud"]
    var ok = false
    if aud.kind == JString:
      ok = aud.getStr() in c.audience
    elif aud.kind == JArray:
      for item in aud:
        if item.kind == JString and item.getStr() in c.audience:
          ok = true
    if not ok:
      joseFail("JWT audience mismatch")
  claims

# ---------------------------------------------------------------------------
# Signed JWT (JWS compact)
# ---------------------------------------------------------------------------

proc jwtSign*(b: JwtBuilder, alg: JwsAlg, key: Jwk,
              protectedExtra: JsonNode = nil): string =
  ## Sign the built claims, returning a JWS compact serialization.
  jwsSign(alg, key, $b.claims, protectedExtra)

proc jwtVerify*(token: string, key: Jwk, c: JwtChecker,
                allowAlgs: openArray[JwsAlg] = []): JsonNode =
  ## Verify the signature and validate claims. Returns the claims.
  let v = jwsVerify(token, key, allowAlgs)
  var claims: JsonNode
  try:
    claims = parseJson(payloadStr(v.payload))
  except JsonParsingError:
    joseFail("JWT payload is not valid JSON")
  c.checkClaims(claims)

# ---------------------------------------------------------------------------
# Encrypted JWT (JWE compact)
# ---------------------------------------------------------------------------

proc jwtEncrypt*(b: JwtBuilder, alg: JweAlg, enc: JweEnc, key: Jwk,
                 protectedExtra: JsonNode = nil,
                 apu: openArray[byte] = [], apv: openArray[byte] = [],
                 p2c = 100_000): string =
  ## Encrypt the built claims, returning a JWE compact serialization.
  jweEncrypt(alg, enc, key, sb($b.claims), protectedExtra, apu, apv, p2c)

proc jwtDecrypt*(token: string, key: Jwk, c: JwtChecker,
                 allowAlgs: openArray[JweAlg] = [],
                 allowEncs: openArray[JweEnc] = []): JsonNode =
  ## Decrypt and validate claims. Returns the claims.
  let d = jweDecrypt(token, key, allowAlgs, allowEncs)
  var claims: JsonNode
  try:
    claims = parseJson(payloadStr(d.plaintext))
  except JsonParsingError:
    joseFail("JWT payload is not valid JSON")
  c.checkClaims(claims)
