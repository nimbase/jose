# JSON Web Signature (JWS, RFC 7515): compact serialization.
#
# Signing algs: HS256/384/512, RS256/384/512, PS256/384/512,
# ES256/384/512, ES256K, EdDSA. `none` is rejected unless the caller
# explicitly opts in with allowNone = true.
#
# (c) 2026 George Lemon | MIT License

import std/json
import std/strutils

import nimcypher/hash as cyHash
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/algos/ed25519 as ed25519Algo

import ./b64
import ./errors
import ./jwk

const
  HsAlgs* = ["HS256", "HS384", "HS512"]
  RsAlgs* = ["RS256", "RS384", "RS512"]
  PsAlgs* = ["PS256", "PS384", "PS512"]
  EsAlgs* = ["ES256", "ES384", "ES512", "ES256K"]

proc rsaHash(alg: string): RsaHash =
  case alg[^3 .. ^1]
  of "256": rhSha256
  of "384": rhSha384
  of "512": rhSha512
  else: joseFail("unsupported JWS alg: " & alg)

proc esCurve(alg: string): EcCurve =
  case alg
  of "ES256": P256
  of "ES384": P384
  of "ES512": P521
  of "ES256K": Secp256k1
  else: joseFail("unsupported JWS alg: " & alg)

proc checkKeyAlg(alg: string, key: Jwk) =
  ## Reject alg/key-type mismatches before touching crypto.
  if alg in HsAlgs:
    if key.kind != jwkOct: joseFail("alg " & alg & " needs an oct key")
  elif alg in RsAlgs or alg in PsAlgs:
    if key.kind != jwkRSA: joseFail("alg " & alg & " needs an RSA key")
  elif alg in EsAlgs:
    if key.kind != jwkEC: joseFail("alg " & alg & " needs an EC key")
    if key.ecCurve != esCurve(alg):
      joseFail("alg " & alg & " needs curve " & ecCrvFromCurve(esCurve(alg)))
  elif alg == "EdDSA":
    if key.kind != jwkOKP or key.okpCrv != "Ed25519":
      joseFail("alg EdDSA needs an Ed25519 key")
  else:
    joseFail("unsupported JWS alg: " & alg)

# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

proc rawSign(alg: string, key: Jwk, signingInput: openArray[byte]): seq[byte] =
  if not key.hasPrivate:
    joseFail("signing needs a private key")
  if alg in HsAlgs:
    let mac =
      case alg
      of "HS256": @(cyHash.sha256Hmac(key.oct, signingInput))
      of "HS384": @(cyHash.sha384Hmac(key.oct, signingInput))
      else: @(cyHash.sha512Hmac(key.oct, signingInput))
    return mac
  elif alg in RsAlgs:
    requireRsaCrt(key)
    return rsaAlgo.pkcs1v15Sign(key.rsaPriv, rsaHash(alg), signingInput)
  elif alg in PsAlgs:
    requireRsaCrt(key)
    return rsaAlgo.pssSign(key.rsaPriv, rsaHash(alg), signingInput)
  elif alg in EsAlgs:
    return ecdsaAlgo.sign(key.ecPriv, signingInput)
  elif alg == "EdDSA":
    var sk: array[64, byte]
    for i in 0 ..< 32: sk[i] = key.okpSeed[i]
    for i in 0 ..< 32: sk[32 + i] = key.okpPub[i]
    let sig = ed25519Algo.ed25519Sign(signingInput, sk)
    return @(sig)
  joseFail("unsupported JWS alg: " & alg)

proc buildProtected(alg: string, key: Jwk,
                    extra: JsonNode = nil): string =
  var hdr = %*{"alg": alg}
  if key.kid.len > 0:
    hdr["kid"] = %key.kid
  if not extra.isNil:
    if extra.kind != JObject:
      joseFail("protected header extra must be an object")
    for k, v in extra:
      hdr[k] = v
  b64urlEncode($hdr)

proc jwsSign*(alg: string, key: Jwk, payload: openArray[byte],
              protectedExtra: JsonNode = nil): string =
  ## Sign `payload`, returning the JWS compact serialization.
  checkKeyAlg(alg, key)
  let h = buildProtected(alg, key, protectedExtra)
  let p = b64urlEncode(payload)
  let signingInput = h & "." & p
  result = signingInput & "." &
    b64urlEncode(rawSign(alg, key, signingInput.toOpenArrayByte(
      0, signingInput.len - 1)))

proc jwsSign*(alg: string, key: Jwk, payload: string,
              protectedExtra: JsonNode = nil): string =
  if payload.len == 0:
    jwsSign(alg, key, [], protectedExtra)
  else:
    jwsSign(alg, key, payload.toOpenArrayByte(0, payload.len - 1),
            protectedExtra)

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

type
  JwsVerified* = object
    ## Result of a successful verification.
    payload*: seq[byte]
    header*: JsonNode

proc rawVerify(alg: string, key: Jwk, signingInput, sig: openArray[byte]) =
  ## Raises JoseError when the signature is invalid.
  var ok = false
  if alg in HsAlgs:
    let expect =
      case alg
      of "HS256": @(cyHash.sha256Hmac(key.oct, signingInput))
      of "HS384": @(cyHash.sha384Hmac(key.oct, signingInput))
      else: @(cyHash.sha512Hmac(key.oct, signingInput))
    ok = cyHash.verifyDigest(expect, sig) and expect.len == sig.len
  elif alg in RsAlgs:
    ok = rsaAlgo.pkcs1v15Verify(key.rsaPub, rsaHash(alg), signingInput, sig)
  elif alg in PsAlgs:
    ok = rsaAlgo.pssVerify(key.rsaPub, rsaHash(alg), signingInput, sig)
  elif alg in EsAlgs:
    ok = ecdsaAlgo.verify(key.ecPub, signingInput, sig)
  elif alg == "EdDSA":
    if sig.len != 64:
      joseFail("EdDSA signature must be 64 bytes")
    var s: array[64, byte]
    for i in 0 ..< 64: s[i] = sig[i]
    ok = ed25519Algo.ed25519Check(s, key.okpPub, signingInput)
  else:
    joseFail("unsupported JWS alg: " & alg)
  if not ok:
    joseFail("JWS signature verification failed")

proc jwsVerify*(token: string, key: Jwk,
                allowAlgs: openArray[string] = [],
                allowNone = false): JwsVerified =
  ## Verify a JWS compact serialization. Returns payload + protected
  ## header. `allowAlgs` restricts acceptable algs (empty = any known).
  let parts = token.split('.')
  if parts.len != 3:
    joseFail("malformed JWS compact serialization")
  let hdr =
    try: parseJson(b64urlDecodeStr(parts[0]))
    except JsonParsingError: joseFail("JWS header is not valid JSON")
  if hdr.kind != JObject:
    joseFail("JWS header must be an object")
  if hdr.hasKey("crit"):
    joseFail("unsupported crit header extensions")
  if not hdr.hasKey("alg") or hdr["alg"].kind != JString:
    joseFail("JWS header missing alg")
  let alg = hdr["alg"].getStr()
  if alg == "none":
    if not allowNone:
      joseFail("unsecured JWS (alg none) rejected")
    if parts[2].len != 0:
      joseFail("unsecured JWS must have empty signature")
    return JwsVerified(payload: b64urlDecode(parts[1]), header: hdr)
  if allowAlgs.len > 0 and alg notin allowAlgs:
    joseFail("JWS alg not allowed: " & alg)
  checkKeyAlg(alg, key)
  let signingInput = parts[0] & "." & parts[1]
  rawVerify(alg, key,
    signingInput.toOpenArrayByte(0, signingInput.len - 1),
    b64urlDecode(parts[2]))
  JwsVerified(payload: b64urlDecode(parts[1]), header: hdr)

proc jwsVerifyStr*(token: string, key: Jwk,
                   allowAlgs: openArray[string] = [],
                   allowNone = false): string =
  ## Verify and return the payload as a string.
  let v = jwsVerify(token, key, allowAlgs, allowNone)
  result = newString(v.payload.len)
  for i in 0 ..< v.payload.len:
    result[i] = char(v.payload[i])
