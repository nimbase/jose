# JSON Web Key (JWK, RFC 7517) and JWK Set handling.
#
# Key material lives in nimcypher key objects; this module parses,
# serializes, validates, and converts them (including RFC 7638
# thumbprints and `kid` lookup over a JWK Set).
#
# (c) 2026 George Lemon | MIT License

import std/json
import std/sysrand

import pkg/bigints

import nimcypher/algos/rsa as rsaAlgo
import nimcypher/algos/ecdsa as ecdsaAlgo
# NOTE: nimcypher/algos/eddsa is Monocypher's BLAKE2b-based EdDSA, NOT
# RFC 8032 Ed25519. JOSE must use nimcypher/algos/ed25519 (SHA-512).
import nimcypher/algos/ed25519 as ed25519Algo
import nimcypher/algos/x25519 as x25519Algo
import nimcypher/algos/bigint_ext
import nimcypher/hash

import ./b64
import ./errors

type
  JwkKind* = enum
    jwkOct, jwkRSA, jwkEC, jwkOKP

  Jwk* = object
    ## A JSON Web Key. Private material is present only when
    ## `hasPrivate` is true; use `jwkToPublic` to strip it.
    kid*: string
    case kind*: JwkKind
    of jwkOct:
      oct*: seq[byte]
    of jwkRSA:
      rsaPub*: RsaPublicKey
      rsaHasPrivate*: bool
      rsaCrt*: bool ## false when only n/e/d are known (no CRT params)
      rsaPriv*: RsaPrivateKey ## valid when rsaHasPrivate and rsaCrt
      rsaD*: BigInt ## valid when rsaHasPrivate (CRT or d-only)
    of jwkEC:
      ecCurve*: EcCurve
      ecPub*: EcPublicKey
      ecHasPrivate*: bool
      ecPriv*: EcPrivateKey ## valid when ecHasPrivate
    of jwkOKP: ## Ed25519 (sign) or X25519 (ECDH-ES)
      okpCrv*: string
      okpPub*: array[32, byte]
      okpHasPrivate*: bool
      okpSeed*: array[32, byte] ## valid when okpHasPrivate

const minRsaBits = 2048
const minOctBytes = 16

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

proc hasPrivate*(key: Jwk): bool =
  case key.kind
  of jwkOct: true
  of jwkRSA: key.rsaHasPrivate
  of jwkEC: key.ecHasPrivate
  of jwkOKP: key.okpHasPrivate

proc getStr(node: JsonNode, field: string): string =
  if not node.hasKey(field):
    joseFail("JWK missing required member: " & field)
  let v = node[field]
  if v.kind != JString:
    joseFail("JWK member must be a string: " & field)
  v.getStr()

proc uintParam(node: JsonNode, field: string): BigInt =
  fromBytesBE(b64urlDecode(getStr(node, field)))

proc fixedParam(node: JsonNode, field: string, size: int): seq[byte] =
  result = b64urlDecode(getStr(node, field))
  if result.len != size:
    joseFail("JWK member has wrong length: " & field)

proc ecCurveFromCrv*(s: string): EcCurve =
  case s
  of "P-256": P256
  of "P-384": P384
  of "P-521": P521
  of "secp256k1": Secp256k1
  else: joseFail("unsupported EC curve: " & s)

proc ecCrvFromCurve*(c: EcCurve): string =
  case c
  of P256: "P-256"
  of P384: "P-384"
  of P521: "P-521"
  of Secp256k1: "secp256k1"

# ---------------------------------------------------------------------------
# Constructors
# ---------------------------------------------------------------------------

proc jwkOctKey*(raw: openArray[byte], kid = ""): Jwk =
  ## Build a symmetric (`oct`) key. Minimum 128 bits.
  if raw.len < minOctBytes:
    joseFail("oct key too short (minimum 128 bits)")
  Jwk(kind: jwkOct, kid: kid, oct: @raw)

proc jwkPassword*(raw: openArray[byte], kid = ""): Jwk =
  ## Build a password key for PBES2 (no length floor; the PBKDF2
  ## iteration count is the work factor). MUST NOT be used as an HMAC,
  ## KEK, or CEK key.
  Jwk(kind: jwkOct, kid: kid, oct: @raw)

proc jwkOctGenerate*(bits = 256, kid = ""): Jwk =
  ## Generate a random symmetric key (`bits` must be a multiple of 8).
  if bits < 128 or (bits mod 8) != 0:
    joseFail("oct key size must be a multiple of 8 >= 128")
  jwkOctKey(urandom(bits div 8), kid)

proc checkRsaSize(n: BigInt) =
  if bitLen(n) < minRsaBits:
    joseFail("RSA modulus too small (minimum 2048 bits)")

proc jwkRsa*(n, e: BigInt, kid = ""): Jwk =
  ## Build a public RSA key from modulus and exponent.
  checkRsaSize(n)
  try:
    Jwk(kind: jwkRSA, kid: kid, rsaPub: rsaAlgo.rsaPublicKey(n, e))
  except ValueError as err:
    joseFail("invalid RSA public key: " & err.msg)

proc jwkRsaPrivate*(n, e, d, p, q: BigInt, kid = ""): Jwk =
  ## Build a private RSA key with CRT parameters.
  checkRsaSize(n)
  try:
    let priv = rsaAlgo.rsaPrivateKey(n, e, d, p, q)
    Jwk(kind: jwkRSA, kid: kid, rsaPub: rsaAlgo.publicKey(priv),
        rsaHasPrivate: true, rsaCrt: true, rsaPriv: priv, rsaD: d)
  except ValueError as err:
    joseFail("invalid RSA private key: " & err.msg)

proc jwkRsaPrivateBare*(n, e, d: BigInt, kid = ""): Jwk =
  ## Build a private RSA key from n/e/d only (no CRT params; slower ops).
  checkRsaSize(n)
  if d <= initBigInt(0):
    joseFail("invalid RSA private exponent")
  try:
    Jwk(kind: jwkRSA, kid: kid, rsaPub: rsaAlgo.rsaPublicKey(n, e),
        rsaHasPrivate: true, rsaCrt: false, rsaD: d)
  except ValueError as err:
    joseFail("invalid RSA public key: " & err.msg)

proc jwkRsaGenerate*(bits = 2048, kid = ""): Jwk =
  ## Generate an RSA key pair (slow for large sizes; prefer imports).
  if bits < minRsaBits:
    joseFail("RSA key size must be >= 2048 bits")
  let priv = rsaAlgo.generateRsaKeyPair(bits)
  Jwk(kind: jwkRSA, kid: kid, rsaPub: rsaAlgo.publicKey(priv),
      rsaHasPrivate: true, rsaCrt: true, rsaPriv: priv, rsaD: priv.d)

proc checkEcKey(curve: EcCurve, x, y: BigInt) =
  let pub = EcPublicKey(curve: curve, x: x, y: y)
  if not ecdsaAlgo.validatePublicKey(pub):
    joseFail("EC public key is not a valid curve point")

proc jwkEc*(curve: EcCurve, x, y: BigInt, kid = ""): Jwk =
  ## Build a public EC key; the point is validated on-curve.
  checkEcKey(curve, x, y)
  Jwk(kind: jwkEC, kid: kid, ecCurve: curve,
      ecPub: EcPublicKey(curve: curve, x: x, y: y))

proc jwkEcPrivate*(curve: EcCurve, d: BigInt, kid = ""): Jwk =
  ## Build a private EC key; the public point is derived.
  let cp = ecdsaAlgo.curveParams(curve)
  if d <= initBigInt(0) or d >= cp.n:
    joseFail("EC private scalar out of range")
  let priv = EcPrivateKey(curve: curve, d: d)
  Jwk(kind: jwkEC, kid: kid, ecCurve: curve,
      ecPub: ecdsaAlgo.publicKeyFromPrivate(priv),
      ecHasPrivate: true, ecPriv: priv)

proc jwkEcGenerate*(curve: EcCurve, kid = ""): Jwk =
  ## Generate an EC key pair.
  let (priv, pub) = ecdsaAlgo.generateKeyPair(curve)
  Jwk(kind: jwkEC, kid: kid, ecCurve: curve, ecPub: pub,
      ecHasPrivate: true, ecPriv: priv)

proc jwkOkpFromSeed*(seed: array[32, byte], kid = ""): Jwk =
  ## Build a private Ed25519 key from its 32-byte seed (RFC 8032).
  let (_, pub) = ed25519Algo.ed25519KeyPair(seed)
  Jwk(kind: jwkOKP, kid: kid, okpCrv: "Ed25519", okpPub: pub,
      okpHasPrivate: true, okpSeed: seed)

proc jwkOkpFromPub*(pub: array[32, byte], kid = ""): Jwk =
  ## Build a public Ed25519 key.
  Jwk(kind: jwkOKP, kid: kid, okpCrv: "Ed25519", okpPub: pub)

proc jwkX25519FromSeed*(seed: array[32, byte], kid = ""): Jwk =
  ## Build a private X25519 key from its 32-byte scalar (RFC 8037 §3.2).
  Jwk(kind: jwkOKP, kid: kid, okpCrv: "X25519",
      okpPub: x25519Algo.x25519PublicKey(seed),
      okpHasPrivate: true, okpSeed: seed)

proc jwkX25519FromPub*(pub: array[32, byte], kid = ""): Jwk =
  ## Build a public X25519 key.
  Jwk(kind: jwkOKP, kid: kid, okpCrv: "X25519", okpPub: pub)

proc randomSeed32(): array[32, byte] =
  let raw = urandom(32)
  for i in 0 ..< 32: result[i] = raw[i]

proc jwkX25519Generate*(kid = ""): Jwk =
  ## Generate a random X25519 key pair.
  jwkX25519FromSeed(randomSeed32(), kid)

proc jwkEd25519Generate*(kid = ""): Jwk =
  ## Generate a random Ed25519 key pair for signing.
  jwkOkpFromSeed(randomSeed32(), kid)

proc jwkOkpGenerate*(crv = "Ed25519", kid = ""): Jwk =
  ## Generate a random OKP key pair. `crv` is "Ed25519" (signing)
  ## or "X25519" (ECDH-ES).
  case crv
  of "Ed25519": jwkOkpFromSeed(randomSeed32(), kid)
  of "X25519": jwkX25519FromSeed(randomSeed32(), kid)
  else: joseFail("unsupported OKP curve: " & crv)

# ---------------------------------------------------------------------------
# JSON parsing / serialization
# ---------------------------------------------------------------------------

proc jwkFromJson*(node: JsonNode): Jwk =
  ## Parse a JWK from JSON. Raises JoseError on any malformed input.
  ## Unknown members are ignored.
  if node.kind != JObject:
    joseFail("JWK must be a JSON object")
  let kty = getStr(node, "kty")
  var kid = ""
  if node.hasKey("kid"):
    if node["kid"].kind != JString:
      joseFail("JWK kid must be a string")
    kid = node["kid"].getStr()
  case kty
  of "oct":
    jwkOctKey(b64urlDecode(getStr(node, "k")), kid)
  of "RSA":
    let n = uintParam(node, "n")
    let e = uintParam(node, "e")
    if node.hasKey("d"):
      let d = uintParam(node, "d")
      if node.hasKey("p") and node.hasKey("q"):
        jwkRsaPrivate(n, e, d, uintParam(node, "p"),
                      uintParam(node, "q"), kid)
      else:
        jwkRsaPrivateBare(n, e, d, kid)
    else:
      jwkRsa(n, e, kid)
  of "EC":
    let curve = ecCurveFromCrv(getStr(node, "crv"))
    let coordLen = ecdsaAlgo.curveParams(curve).coordLen
    let x = fromBytesBE(fixedParam(node, "x", coordLen))
    let y = fromBytesBE(fixedParam(node, "y", coordLen))
    if node.hasKey("d"):
      let dbytes = fixedParam(node, "d", coordLen)
      let d = fromBytesBE(dbytes)
      let key = jwkEcPrivate(curve, d, kid)
      # The derived public point must match the stated one.
      if key.ecPub.x != x or key.ecPub.y != y:
        joseFail("EC private scalar does not match public point")
      key
    else:
      jwkEc(curve, x, y, kid)
  of "OKP":
    let crv = getStr(node, "crv")
    if crv != "Ed25519" and crv != "X25519":
      joseFail("unsupported OKP curve: " & crv)
    let xbytes = fixedParam(node, "x", 32)
    var pub: array[32, byte]
    for i in 0 ..< 32: pub[i] = xbytes[i]
    if node.hasKey("d"):
      let dbytes = fixedParam(node, "d", 32)
      var seed: array[32, byte]
      for i in 0 ..< 32: seed[i] = dbytes[i]
      let key =
        if crv == "Ed25519": jwkOkpFromSeed(seed, kid)
        else: jwkX25519FromSeed(seed, kid)
      if key.okpPub != pub:
        joseFail("OKP seed does not match public key")
      key
    else:
      if crv == "Ed25519": jwkOkpFromPub(pub, kid)
      else: jwkX25519FromPub(pub, kid)
  else:
    joseFail("unsupported JWK kty: " & kty)

proc jwkFromJsonStr*(s: string): Jwk =
  var node: JsonNode
  try:
    node = parseJson(s)
  except JsonParsingError:
    joseFail("JWK is not valid JSON")
  jwkFromJson(node)

proc jwkToJson*(key: Jwk, includePrivate = false): JsonNode =
  ## Serialize a JWK. Private material is included only when
  ## `includePrivate` is true (and present).
  result = newJObject()
  if key.kid.len > 0:
    result["kid"] = %key.kid
  case key.kind
  of jwkOct:
    result["kty"] = %"oct"
    result["k"] = %b64urlEncode(key.oct)
  of jwkRSA:
    result["kty"] = %"RSA"
    result["n"] = %b64urlEncodeInt(toBytesBETrimmed(key.rsaPub.n))
    result["e"] = %b64urlEncodeInt(toBytesBETrimmed(key.rsaPub.e))
    if includePrivate and key.rsaHasPrivate:
      let k = key.rsaPub.k
      result["d"] = %b64urlEncodeInt(toBytesBE(key.rsaD, k))
      if key.rsaCrt:
        let p = key.rsaPriv.p
        let q = key.rsaPriv.q
        result["p"] = %b64urlEncodeInt(toBytesBETrimmed(p))
        result["q"] = %b64urlEncodeInt(toBytesBETrimmed(q))
        result["dp"] = %b64urlEncodeInt(toBytesBETrimmed(key.rsaPriv.dp))
        result["dq"] = %b64urlEncodeInt(toBytesBETrimmed(key.rsaPriv.dq))
        result["qi"] = %b64urlEncodeInt(toBytesBETrimmed(key.rsaPriv.qinv))
  of jwkEC:
    let coordLen = ecdsaAlgo.curveParams(key.ecCurve).coordLen
    result["kty"] = %"EC"
    result["crv"] = %ecCrvFromCurve(key.ecCurve)
    result["x"] = %b64urlEncodeInt(toBytesBE(key.ecPub.x, coordLen))
    result["y"] = %b64urlEncodeInt(toBytesBE(key.ecPub.y, coordLen))
    if includePrivate and key.ecHasPrivate:
      result["d"] = %b64urlEncodeInt(toBytesBE(key.ecPriv.d, coordLen))
  of jwkOKP:
    result["kty"] = %"OKP"
    result["crv"] = %key.okpCrv
    result["x"] = %b64urlEncode(key.okpPub)
    if includePrivate and key.okpHasPrivate:
      result["d"] = %b64urlEncode(key.okpSeed)

proc jwkToPublic*(key: Jwk): Jwk =
  ## Return the public part of a key (no-op for public keys).
  case key.kind
  of jwkOct:
    key
  of jwkRSA:
    Jwk(kind: jwkRSA, kid: key.kid, rsaPub: key.rsaPub)
  of jwkEC:
    Jwk(kind: jwkEC, kid: key.kid, ecCurve: key.ecCurve, ecPub: key.ecPub)
  of jwkOKP:
    Jwk(kind: jwkOKP, kid: key.kid, okpCrv: key.okpCrv, okpPub: key.okpPub)

# ---------------------------------------------------------------------------
# JWK Set
# ---------------------------------------------------------------------------

proc jwksFromJson*(node: JsonNode): seq[Jwk] =
  ## Parse a JWK Set (`{"keys": [...]}`). Raises JoseError on bad input.
  if node.kind != JObject or not node.hasKey("keys"):
    joseFail("JWK Set must be an object with a keys array")
  let arr = node["keys"]
  if arr.kind != JArray:
    joseFail("JWK Set keys must be an array")
  for item in arr:
    result.add(jwkFromJson(item))

proc jwksFind*(keys: openArray[Jwk], kid: string): Jwk =
  ## Find a key by `kid`. An empty `kid` matches only when exactly one
  ## key is present. Raises JoseError when ambiguous or missing.
  if kid.len == 0:
    if keys.len == 1:
      return keys[0]
    joseFail("missing kid with multiple keys in set")
  for key in keys:
    if key.kid == kid:
      return key
  joseFail("no key found for kid: " & kid)

# ---------------------------------------------------------------------------
# Thumbprint (RFC 7638, SHA-256)
# ---------------------------------------------------------------------------

proc jwkThumbprint*(key: Jwk): string =
  ## RFC 7638 JWK SHA-256 thumbprint (public members only).
  var canonical: string
  case key.kind
  of jwkOct:
    canonical = "{\"k\":\"" & b64urlEncode(key.oct) &
      "\",\"kty\":\"oct\"}"
  of jwkRSA:
    canonical = "{\"e\":\"" &
      b64urlEncodeInt(toBytesBETrimmed(key.rsaPub.e)) &
      "\",\"kty\":\"RSA\",\"n\":\"" &
      b64urlEncodeInt(toBytesBETrimmed(key.rsaPub.n)) & "\"}"
  of jwkEC:
    let coordLen = ecdsaAlgo.curveParams(key.ecCurve).coordLen
    canonical = "{\"crv\":\"" & ecCrvFromCurve(key.ecCurve) &
      "\",\"kty\":\"EC\",\"x\":\"" &
      b64urlEncodeInt(toBytesBE(key.ecPub.x, coordLen)) &
      "\",\"y\":\"" &
      b64urlEncodeInt(toBytesBE(key.ecPub.y, coordLen)) & "\"}"
  of jwkOKP:
    canonical = "{\"crv\":\"" & key.okpCrv & "\",\"kty\":\"OKP\",\"x\":\"" &
      b64urlEncode(key.okpPub) & "\"}"
  b64urlEncode(sha256(canonical))

# ---------------------------------------------------------------------------
# Private-operation guard for d-only RSA keys
# ---------------------------------------------------------------------------

proc requireRsaCrt*(key: Jwk) =
  ## Private RSA operations (sign, decrypt) need CRT parameters.
  ## d-only keys (n/e/d without p/q) parse and verify fine, but private
  ## ops raise here instead of duplicating EMSA/OAEP codecs without
  ## blinding. Re-import the key with p/q to enable them.
  if key.kind != jwkRSA or not key.rsaHasPrivate:
    joseFail("RSA private key required")
  if not key.rsaCrt:
    joseFail("RSA private operation needs CRT parameters (p, q)")
