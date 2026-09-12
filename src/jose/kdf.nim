# Key derivation for JWE: Concat-KDF (RFC 7518 4.6.2) and
# PBES2 password-based KEK derivation (RFC 7518 4.8, RFC 2898).
#
# (c) 2026 George Lemon | MIT License

import std/strutils

import nimcypher/hash as cyHash

import ./errors

proc be32(v: int): array[4, byte] =
  result[0] = byte((v shr 24) and 0xFF)
  result[1] = byte((v shr 16) and 0xFF)
  result[2] = byte((v shr 8) and 0xFF)
  result[3] = byte(v and 0xFF)

proc lenPrefixed(data: openArray[byte]): seq[byte] =
  let n = be32(data.len)
  result = newSeq[byte](4 + data.len)
  for i in 0 ..< 4: result[i] = n[i]
  for i in 0 ..< data.len: result[4 + i] = data[i]

proc concatKdf*(z: openArray[byte], keyLenBits: int, algorithmId: string,
                apu: openArray[byte] = [],
                apv: openArray[byte] = []): seq[byte] =
  ## Concat-KDF with SHA-256 (RFC 7518 §4.6.2, NIST.800-56A §5.8.1).
  ## `algorithmId` is the `enc` value (direct mode) or the `alg` value
  ## (key-wrapping mode); `apu`/`apv` are the decoded PartyU/VInfo.
  if keyLenBits <= 0 or (keyLenBits mod 8) != 0:
    joseFail("Concat-KDF key length must be a positive multiple of 8")
  if keyLenBits > 0x7FFFFFFF:
    joseFail("Concat-KDF key length too large")
  var otherInfo: seq[byte]
  if algorithmId.len == 0:
    joseFail("Concat-KDF needs an AlgorithmID")
  otherInfo.add(lenPrefixed(algorithmId.toOpenArrayByte(
    0, algorithmId.len - 1)))
  otherInfo.add(lenPrefixed(apu))
  otherInfo.add(lenPrefixed(apv))
  let supp = be32(keyLenBits)
  otherInfo.add(@supp)
  let reps = (keyLenBits + 255) div 256
  if reps > 0xFFFFFFFF:
    joseFail("Concat-KDF key length too large")
  result = newSeq[byte]()
  for i in 1 .. reps:
    let counter = be32(i)
    var input = newSeq[byte](4 + z.len + otherInfo.len)
    for k in 0 ..< 4: input[k] = counter[k]
    for k in 0 ..< z.len: input[4 + k] = z[k]
    for k in 0 ..< otherInfo.len: input[4 + z.len + k] = otherInfo[k]
    let digest = cyHash.sha256(input)
    result.add(@digest)
  result.setLen(keyLenBits div 8)

# ---------------------------------------------------------------------------
# PBES2 (PBKDF2-HMAC-SHA2 + salt binding, RFC 7518 4.8)
# ---------------------------------------------------------------------------

proc prf(key, data: openArray[byte], hashBits: int): seq[byte] =
  case hashBits
  of 256: @(cyHash.sha256Hmac(key, data))
  of 384: @(cyHash.sha384Hmac(key, data))
  of 512: @(cyHash.sha512Hmac(key, data))
  else: joseFail("PBES2 needs SHA-256, SHA-384, or SHA-512")

proc pbkdf2(password, salt: openArray[byte], iterations, dkLen,
            hashBits: int): seq[byte] =
  if iterations <= 0:
    joseFail("PBES2 iteration count must be positive")
  if dkLen <= 0 or dkLen > (0xFFFFFFFF'u64 * uint64(hashBits div 8)).int:
    joseFail("PBES2 derived key length out of range")
  let hLen = hashBits div 8
  result = newSeq[byte]()
  var blk = 1
  while result.len < dkLen:
    let counter = be32(blk)
    var saltBlk = newSeq[byte](salt.len + 4)
    for i in 0 ..< salt.len: saltBlk[i] = salt[i]
    for i in 0 ..< 4: saltBlk[salt.len + i] = counter[i]
    var u = prf(password, saltBlk, hashBits)
    var t = u
    for _ in 2 .. iterations:
      u = prf(password, u, hashBits)
      for i in 0 ..< hLen: t[i] = t[i] xor u[i]
    result.add(t)
    inc blk
  result.setLen(dkLen)

proc pbes2Salt*(alg: string, p2s: openArray[byte]): seq[byte] =
  ## Salt = ASCII(alg) || 0x00 || p2s (RFC 7518 §4.8.1.1).
  result = newSeq[byte](alg.len + 1 + p2s.len)
  for i in 0 ..< alg.len: result[i] = byte(alg[i])
  result[alg.len] = 0
  for i in 0 ..< p2s.len: result[alg.len + 1 + i] = p2s[i]

proc pbes2Derive*(password: openArray[byte], alg: string,
                  p2s: openArray[byte], p2c: int, hashBits: int,
                  kekLen: int): seq[byte] =
  ## Derive a KEK of `kekLen` bytes via PBES2 (RFC 7518 §4.8).
  ## `hashBits` selects HS256/384/512; minimum 1000 iterations enforced.
  if p2c < 1000:
    joseFail("PBES2 iteration count below minimum 1000")
  pbkdf2(password, pbes2Salt(alg, p2s), p2c, kekLen, hashBits)

proc pbes2HashBits*(alg: string): int =
  ## PRF hash size for a PBES2 alg value.
  if alg.startsWith("PBES2-HS256+"):
    256
  elif alg.startsWith("PBES2-HS384+"):
    384
  elif alg.startsWith("PBES2-HS512+"):
    512
  else:
    joseFail("unsupported PBES2 alg: " & alg)
