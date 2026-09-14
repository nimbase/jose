# JSON Web Encryption (JWE, RFC 7516): compact serialization.
#
# Key management (`alg`): dir, A128KW/A192KW/A256KW, RSA-OAEP,
# RSA-OAEP-256, RSA1_5 (legacy), ECDH-ES / ECDH-ES+A*KW (P-256/384/521
# and X25519), PBES2-HS256+A128KW / PBES2-HS384+A192KW /
# PBES2-HS512+A256KW. A*GCMKW and `zip` are rejected (unsupported).
# Content encryption (`enc`): A128CBC-HS256, A192CBC-HS384,
# A256CBC-HS512, A128GCM, A192GCM, A256GCM, C20P.
#
# (c) 2026 George Lemon | MIT License

import std/json
import std/options
import std/strutils
import std/sysrand

import nimcypher/hash as cyHash
import nimcypher/aes as cyAes
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/algos/x25519 as x25519Algo
import nimcypher/algos/aead as aeadAlgo

import ./b64
import ./errors
import ./algs
import ./jwk
import ./kw
import ./kdf

const
  KwAlgs* = [A128KW, A192KW, A256KW]
  EcdhKwAlgs* = [ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW]

type
  JweDecrypted* = object
    ## Result of a successful decryption.
    plaintext*: seq[byte]
    header*: JsonNode ## the protected header

# ---------------------------------------------------------------------------
# Algorithm tables
# ---------------------------------------------------------------------------

proc cekLen(enc: JweEnc): int =
  ## Required CEK length in bytes for an `enc` value.
  case enc
  of A128CBC_HS256: 32
  of A192CBC_HS384: 48
  of A256CBC_HS512: 64
  of A128GCM: 16
  of A192GCM: 24
  of A256GCM: 32
  of C20P: 32

proc kwLen(alg: JweAlg): int =
  ## KEK length in bytes for a key-wrapping `alg` value.
  case alg
  of A128KW, ECDH_ES_A128KW, PBES2_HS256_A128KW: 16
  of A192KW, ECDH_ES_A192KW, PBES2_HS384_A192KW: 24
  of A256KW, ECDH_ES_A256KW, PBES2_HS512_A256KW: 32
  else:
    joseFail("unsupported key-wrapping alg: " & $alg)

proc isPbes2(alg: JweAlg): bool =
  alg in [PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW]

proc checkAlgEnc(alg: JweAlg, enc: JweEnc) =
  if alg in [A128GCMKW, A192GCMKW, A256GCMKW]:
    joseFail("AES-GCM key wrapping is not supported")

proc sb(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

proc toArray32(data: openArray[byte]): array[32, byte] =
  if data.len != 32:
    joseFail("expected 32 bytes")
  for i in 0 ..< 32: result[i] = data[i]

proc toArray12(data: openArray[byte]): array[12, byte] =
  if data.len != 12:
    joseFail("expected 12-byte nonce")
  for i in 0 ..< 12: result[i] = data[i]

# ---------------------------------------------------------------------------
# Content encryption (JWA 5.2 / 5.3 + C20P)
# ---------------------------------------------------------------------------

proc cbcParams(enc: JweEnc): tuple[macLen, hashBits, tagLen: int] =
  case enc
  of A128CBC_HS256: (16, 256, 16)
  of A192CBC_HS384: (24, 384, 24)
  of A256CBC_HS512: (32, 512, 32)
  else: joseFail("not a CBC-HMAC enc: " & $enc)

proc be64(v: int): array[8, byte] =
  let bits = v * 8
  for i in 0 ..< 8:
    result[i] = byte((bits shr (56 - 8 * i)) and 0xFF)

proc cbcTag(enc: JweEnc, cek: openArray[byte], aad: openArray[byte],
             iv: openArray[byte], ct: openArray[byte]): seq[byte] =
  ## T = MAC(AAD || IV || CT || AL)[0..tagLen] (RFC 7518 §5.2.2.1).
  let (macLen, hashBits, tagLen) = cbcParams(enc)
  if cek.len != 2 * macLen:
    joseFail("CEK length mismatch for " & $enc)
  var macInput = newSeq[byte](aad.len + iv.len + ct.len + 8)
  var off = 0
  for b in aad: macInput[off] = b; inc off
  for b in iv: macInput[off] = b; inc off
  for b in ct: macInput[off] = b; inc off
  let al = be64(aad.len)
  for b in al: macInput[off] = b; inc off
  let full =
    case hashBits
    of 256: @(cyHash.sha256Hmac(cek.toOpenArray(0, macLen - 1), macInput))
    of 384: @(cyHash.sha384Hmac(cek.toOpenArray(0, macLen - 1), macInput))
    else: @(cyHash.sha512Hmac(cek.toOpenArray(0, macLen - 1), macInput))
  full[0 ..< tagLen]

proc cbcEncrypt(enc: JweEnc, cek: openArray[byte], iv: openArray[byte],
                plaintext: openArray[byte],
                aad: openArray[byte]): tuple[ct, tag: seq[byte]] =
  let (macLen, _, _) = cbcParams(enc)
  if cek.len != 2 * macLen:
    joseFail("CEK length mismatch for " & $enc)
  if iv.len != 16:
    joseFail("CBC-HMAC needs a 128-bit IV")
  let ct = cyAes.aesCbcEncrypt(cek.toOpenArray(macLen, cek.len - 1), iv,
                               plaintext, padded = true)
  (ct, cbcTag(enc, cek, aad, iv, ct))

proc cbcDecrypt(enc: JweEnc, cek: openArray[byte], iv: openArray[byte],
                ct: openArray[byte], tag: openArray[byte],
                aad: openArray[byte]): seq[byte] =
  let (macLen, _, tagLen) = cbcParams(enc)
  if cek.len != 2 * macLen:
    joseFail("CEK length mismatch for " & $enc)
  if iv.len != 16:
    joseFail("CBC-HMAC needs a 128-bit IV")
  if tag.len != tagLen:
    joseFail("authentication tag length mismatch")
  # Verify first (encrypt-then-MAC); constant-time compare.
  if not cyHash.verifyDigest(cbcTag(enc, cek, aad, iv, ct), tag):
    joseFail("JWE authentication failed")
  try:
    cyAes.aesCbcDecrypt(cek.toOpenArray(macLen, cek.len - 1), iv, ct,
                        padded = true)
  except ValueError:
    joseFail("JWE decryption failed")

proc gcmEncrypt(enc: JweEnc, cek: openArray[byte], iv: openArray[byte],
                plaintext: openArray[byte],
                aad: openArray[byte]): tuple[ct, tag: seq[byte]] =
  if cek.len != cekLen(enc):
    joseFail("CEK length mismatch for " & $enc)
  if iv.len != 12:
    joseFail("GCM content encryption needs a 96-bit IV")
  try:
    let (ct, tag) = cyAes.aesGcmEncrypt(cek, iv, plaintext, aad)
    (@ct, @tag)
  except ValueError as err:
    joseFail("JWE encryption failed: " & err.msg)

proc gcmDecrypt(enc: JweEnc, cek: openArray[byte], iv: openArray[byte],
                ct: openArray[byte], tag: openArray[byte],
                aad: openArray[byte]): seq[byte] =
  if cek.len != cekLen(enc):
    joseFail("CEK length mismatch for " & $enc)
  try:
    cyAes.aesGcmDecrypt(cek, iv, ct, tag, aad)
  except ValueError:
    joseFail("JWE authentication failed")

proc c20pCrypt(cek: openArray[byte], iv: openArray[byte],
               input: openArray[byte], aad: openArray[byte],
               encrypting: bool, tag: openArray[byte] = []): tuple[output,
                                                                  tag: seq[byte]] =
  if cek.len != 32:
    joseFail("C20P needs a 256-bit CEK")
  var ctx: aeadAlgo.AeadContext
  try:
    aeadAlgo.initIetf(ctx, toArray32(cek), toArray12(iv))
  except ValueError as err:
    joseFail("JWE encryption failed: " & err.msg)
  if encrypting:
    let (ct, mac) = aeadAlgo.write(ctx, input, aad)
    (@ct, @mac)
  else:
    if tag.len != 16:
      joseFail("authentication tag length mismatch")
    let pt = aeadAlgo.read(ctx, input, tag, aad)
    if pt.isNone:
      joseFail("JWE authentication failed")
    (pt.get, @[])

# ---------------------------------------------------------------------------
# ECDH-ES helpers
# ---------------------------------------------------------------------------

proc ecdhZ(recipientPub: Jwk, ephPriv: Jwk): seq[byte] =
  ## Shared secret Z with an ephemeral private key. Both keys must be
  ## on the same curve (EC) or both X25519 (OKP).
  if recipientPub.kind == jwkEC and ephPriv.kind == jwkEC:
    if recipientPub.ecCurve != ephPriv.ecCurve:
      joseFail("ECDH-ES curve mismatch")
    ecdsaAlgo.ecdh(ephPriv.ecPriv, recipientPub.ecPub)
  elif recipientPub.kind == jwkOKP and ephPriv.kind == jwkOKP:
    if recipientPub.okpCrv != "X25519" or ephPriv.okpCrv != "X25519":
      joseFail("ECDH-ES needs X25519 OKP keys")
    let z = x25519Algo.x25519(ephPriv.okpSeed, recipientPub.okpPub)
    @(z)
  else:
    joseFail("ECDH-ES needs matching EC or X25519 keys")

proc ecdhZDecrypt(recipientPriv: Jwk, epk: Jwk): seq[byte] =
  ## Shared secret Z from the recipient side (private key + epk).
  if recipientPriv.kind == jwkEC and epk.kind == jwkEC:
    if recipientPriv.ecCurve != epk.ecCurve:
      joseFail("ECDH-ES curve mismatch")
    if not recipientPriv.hasPrivate:
      joseFail("ECDH-ES decryption needs the private key")
    ecdsaAlgo.ecdh(recipientPriv.ecPriv, epk.ecPub)
  elif recipientPriv.kind == jwkOKP and epk.kind == jwkOKP:
    if recipientPriv.okpCrv != "X25519" or epk.okpCrv != "X25519":
      joseFail("ECDH-ES needs X25519 OKP keys")
    if not recipientPriv.hasPrivate:
      joseFail("ECDH-ES decryption needs the private key")
    let z = x25519Algo.x25519(recipientPriv.okpSeed, epk.okpPub)
    @(z)
  else:
    joseFail("ECDH-ES needs matching EC or X25519 keys")

proc genEphemeral(recipientPub: Jwk): Jwk =
  ## Fresh ephemeral key on the recipient's curve.
  if recipientPub.kind == jwkEC:
    jwkEcGenerate(recipientPub.ecCurve)
  elif recipientPub.kind == jwkOKP and recipientPub.okpCrv == "X25519":
    jwkX25519Generate()
  else:
    joseFail("ECDH-ES needs an EC or X25519 recipient key")

# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

proc encryptCek(alg: JweAlg, enc: JweEnc, key: Jwk, cek: openArray[byte],
                hdr: var JsonNode, apu, apv: openArray[byte],
                p2c: int): seq[byte] =
  ## Returns the JWE Encrypted Key (empty for dir/ECDH-ES).
  case alg
  of Dir:
    if key.kind != jwkOct or key.oct.len != cekLen(enc):
      joseFail("dir needs an oct key of CEK length")
    @[]
  of A128KW, A192KW, A256KW:
    if key.kind != jwkOct or key.oct.len != kwLen(alg):
      joseFail($alg & " needs an oct KEK")
    aesKwWrap(key.oct, cek)
  of RSA_OAEP:
    if key.kind != jwkRSA:
      joseFail("RSA-OAEP needs an RSA key")
    try:
      rsaAlgo.oaepEncrypt(key.rsaPub, rhSha1, cek)
    except ValueError as err:
      joseFail("JWE key encryption failed: " & err.msg)
  of RSA_OAEP_256:
    if key.kind != jwkRSA:
      joseFail("RSA-OAEP-256 needs an RSA key")
    try:
      rsaAlgo.oaepEncrypt(key.rsaPub, rhSha256, cek)
    except ValueError as err:
      joseFail("JWE key encryption failed: " & err.msg)
  of RSA1_5:
    if key.kind != jwkRSA:
      joseFail("RSA1_5 needs an RSA key")
    try:
      rsaAlgo.pkcs1v15Encrypt(key.rsaPub, cek)
    except ValueError as err:
      joseFail("JWE key encryption failed: " & err.msg)
  of ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW:
    # NOTE: bare ECDH-ES (direct) is handled in jweEncrypt, where the
    # CEK itself is the KDF output rather than a random value.
    let eph = genEphemeral(key)
    let z = ecdhZ(key, eph)
    let derived = concatKdf(z, kwLen(alg) * 8, $alg, apu, apv)
    hdr["epk"] = jwkToJson(jwkToPublic(eph))
    if apu.len > 0: hdr["apu"] = %b64urlEncode(apu)
    if apv.len > 0: hdr["apv"] = %b64urlEncode(apv)
    aesKwWrap(derived, cek)
  of ECDH_ES:
    joseFail("ECDH-ES direct mode handled in jweEncrypt")
  else:
    if isPbes2(alg):
      if key.kind != jwkOct:
        joseFail($alg & " needs the password as an oct key")
      let hashBits = pbes2HashBits(alg)
      let saltInput = urandom(16)
      let kek = pbes2Derive(key.oct, alg, saltInput, p2c, hashBits,
                            kwLen(alg))
      hdr["p2s"] = %b64urlEncode(saltInput)
      hdr["p2c"] = %p2c
      aesKwWrap(kek, cek)
    else:
      joseFail("unsupported JWE alg: " & $alg)

proc jweEncrypt*(alg: JweAlg, enc: JweEnc, key: Jwk,
                 plaintext: openArray[byte],
                 protectedExtra: JsonNode = nil,
                 apu: openArray[byte] = [], apv: openArray[byte] = [],
                 p2c = 100_000): string =
  ## Encrypt, returning the JWE compact serialization. For PBES2 `alg`
  ## values pass the password via `jwkPassword`; `p2c` is the PBKDF2
  ## iteration count.
  checkAlgEnc(alg, enc)
  var hdr = %*{"alg": $alg, "enc": $enc}
  if key.kid.len > 0:
    hdr["kid"] = %key.kid
  if not protectedExtra.isNil:
    if protectedExtra.kind != JObject:
      joseFail("protected header extra must be an object")
    for k, v in protectedExtra:
      hdr[k] = v
  # CEK: random, except direct modes where it is derived/agreed.
  var cek = urandom(cekLen(enc))
  var encryptedKey: seq[byte]
  if alg == Dir:
    if key.kind != jwkOct or key.oct.len != cekLen(enc):
      joseFail("dir needs an oct key of CEK length")
    cek = key.oct
    encryptedKey = @[]
  elif alg == ECDH_ES:
    # Direct agreement: CEK comes from the KDF; generate the ephemeral
    # side first via a throwaway, then replace cek below.
    let eph = genEphemeral(key)
    let z = ecdhZ(key, eph)
    let derived = concatKdf(z, cekLen(enc) * 8, $enc, apu, apv)
    cek = derived
    hdr["epk"] = jwkToJson(jwkToPublic(eph))
    if apu.len > 0: hdr["apu"] = %b64urlEncode(apu)
    if apv.len > 0: hdr["apv"] = %b64urlEncode(apv)
    if key.kid.len > 0: hdr["kid"] = %key.kid
    encryptedKey = @[]
  else:
    encryptedKey = encryptCek(alg, enc, key, cek, hdr, apu, apv, p2c)
  let protectedB64 = b64urlEncode($hdr)
  let aad = sb(protectedB64)
  # Content IV size: 16 bytes for CBC-HMAC, 12 for GCM/C20P.
  let ivLen = if enc in [A128CBC_HS256, A192CBC_HS384,
                         A256CBC_HS512]: 16 else: 12
  let iv = urandom(ivLen)
  var ct, tag: seq[byte]
  if enc in [A128CBC_HS256, A192CBC_HS384, A256CBC_HS512]:
    (ct, tag) = cbcEncrypt(enc, cek, iv, plaintext, aad)
  elif enc in [A128GCM, A192GCM, A256GCM]:
    (ct, tag) = gcmEncrypt(enc, cek, iv, plaintext, aad)
  else:
    (ct, tag) = c20pCrypt(cek, iv, plaintext, aad, true)
  protectedB64 & "." & b64urlEncode(encryptedKey) & "." &
    b64urlEncode(iv) & "." & b64urlEncode(ct) & "." & b64urlEncode(tag)

# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

proc decryptCek(alg: JweAlg, enc: JweEnc, key: Jwk,
                encryptedKey: openArray[byte],
                hdr: JsonNode): seq[byte] =
  case alg
  of Dir:
    if encryptedKey.len != 0:
      joseFail("dir JWE must have empty encrypted key")
    if key.kind != jwkOct or key.oct.len != cekLen(enc):
      joseFail("dir needs an oct key of CEK length")
    key.oct
  of A128KW, A192KW, A256KW:
    if key.kind != jwkOct or key.oct.len != kwLen(alg):
      joseFail($alg & " needs an oct KEK")
    let cek = aesKwUnwrap(key.oct, encryptedKey)
    if cek.len != cekLen(enc):
      joseFail("unwrapped CEK length mismatch")
    cek
  of RSA_OAEP, RSA_OAEP_256:
    if key.kind != jwkRSA:
      joseFail($alg & " needs an RSA key")
    requireRsaCrt(key)
    let h = if alg == RSA_OAEP: rhSha1 else: rhSha256
    var cek: seq[byte]
    try:
      cek = rsaAlgo.oaepDecrypt(key.rsaPriv, h, encryptedKey)
    except ValueError:
      joseFail("JWE key decryption failed")
    if cek.len != cekLen(enc):
      joseFail("decrypted CEK length mismatch")
    cek
  of RSA1_5:
    if key.kind != jwkRSA:
      joseFail("RSA1_5 needs an RSA key")
    requireRsaCrt(key)
    var cek: seq[byte]
    try:
      cek = rsaAlgo.pkcs1v15Decrypt(key.rsaPriv, encryptedKey)
    except ValueError:
      joseFail("JWE key decryption failed")
    if cek.len != cekLen(enc):
      joseFail("decrypted CEK length mismatch")
    cek
  of ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW:
    if not hdr.hasKey("epk") or hdr["epk"].kind != JObject:
      joseFail("ECDH-ES needs an epk header")
    let epk = jwkFromJson(hdr["epk"])
    if epk.hasPrivate:
      joseFail("epk must be a public key")
    var apuB, apvB: seq[byte]
    if hdr.hasKey("apu"):
      if hdr["apu"].kind != JString:
        joseFail("apu must be a string")
      apuB = b64urlDecode(hdr["apu"].getStr())
    if hdr.hasKey("apv"):
      if hdr["apv"].kind != JString:
        joseFail("apv must be a string")
      apvB = b64urlDecode(hdr["apv"].getStr())
    let z = ecdhZDecrypt(key, epk)
    let algorithmId = if alg == ECDH_ES: $enc else: $alg
    let keyLenBits =
      if alg == ECDH_ES: cekLen(enc) * 8 else: kwLen(alg) * 8
    let derived = concatKdf(z, keyLenBits, algorithmId, apuB, apvB)
    if alg == ECDH_ES:
      if encryptedKey.len != 0:
        joseFail("ECDH-ES direct mode needs empty encrypted key")
      derived
    else:
      let cek = aesKwUnwrap(derived, encryptedKey)
      if cek.len != cekLen(enc):
        joseFail("unwrapped CEK length mismatch")
      cek
  else:
    if isPbes2(alg):
      if key.kind != jwkOct:
        joseFail($alg & " needs the password as an oct key")
      if not hdr.hasKey("p2s") or hdr["p2s"].kind != JString:
        joseFail("PBES2 needs a p2s header")
      if not hdr.hasKey("p2c") or hdr["p2c"].kind != JInt:
        joseFail("PBES2 needs a p2c header")
      let p2s = b64urlDecode(hdr["p2s"].getStr())
      let p2c = hdr["p2c"].getInt()
      let hashBits = pbes2HashBits(alg)
      let kek = pbes2Derive(key.oct, alg, p2s, p2c, hashBits, kwLen(alg))
      let cek = aesKwUnwrap(kek, encryptedKey)
      if cek.len != cekLen(enc):
        joseFail("unwrapped CEK length mismatch")
      cek
    else:
      joseFail("unsupported JWE alg: " & $alg)

proc jweDecrypt*(token: string, key: Jwk,
                 allowAlgs: openArray[JweAlg] = [],
                 allowEncs: openArray[JweEnc] = []): JweDecrypted =
  ## Decrypt a JWE compact serialization. Returns plaintext + header.
  let parts = token.split('.')
  if parts.len != 5:
    joseFail("malformed JWE compact serialization")
  let hdr =
    try: parseJson(b64urlDecodeStr(parts[0]))
    except JsonParsingError: joseFail("JWE header is not valid JSON")
  if hdr.kind != JObject:
    joseFail("JWE header must be an object")
  if hdr.hasKey("crit"):
    joseFail("unsupported crit header extensions")
  if hdr.hasKey("zip"):
    joseFail("JWE compression (zip) is not supported")
  if not hdr.hasKey("alg") or hdr["alg"].kind != JString:
    joseFail("JWE header missing alg")
  if not hdr.hasKey("enc") or hdr["enc"].kind != JString:
    joseFail("JWE header missing enc")
  let algStr = hdr["alg"].getStr()
  let encStr = hdr["enc"].getStr()
  let alg = parseJweAlg(algStr)
  let enc = parseJweEnc(encStr)
  if allowAlgs.len > 0 and alg notin allowAlgs:
    joseFail("JWE alg not allowed: " & algStr)
  if allowEncs.len > 0 and enc notin allowEncs:
    joseFail("JWE enc not allowed: " & encStr)
  checkAlgEnc(alg, enc)
  let encryptedKey = b64urlDecode(parts[1])
  let iv = b64urlDecode(parts[2])
  let ct = b64urlDecode(parts[3])
  let tag = b64urlDecode(parts[4])
  let cek = decryptCek(alg, enc, key, encryptedKey, hdr)
  let aad = sb(parts[0])
  var plaintext: seq[byte]
  if enc in [A128CBC_HS256, A192CBC_HS384, A256CBC_HS512]:
    plaintext = cbcDecrypt(enc, cek, iv, ct, tag, aad)
  elif enc in [A128GCM, A192GCM, A256GCM]:
    plaintext = gcmDecrypt(enc, cek, iv, ct, tag, aad)
  else:
    (plaintext, _) = c20pCrypt(cek, iv, ct, aad, false, tag)
  JweDecrypted(plaintext: plaintext, header: hdr)

proc jweDecryptStr*(token: string, key: Jwk,
                    allowAlgs: openArray[JweAlg] = [],
                    allowEncs: openArray[JweEnc] = []): string =
  ## Decrypt and return the plaintext as a string.
  let d = jweDecrypt(token, key, allowAlgs, allowEncs)
  result = newString(d.plaintext.len)
  for i in 0 ..< d.plaintext.len:
    result[i] = char(d.plaintext[i])
