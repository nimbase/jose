# AES Key Wrap (RFC 3394) for JWE A128KW/A192KW/A256KW.
#
# Single-block AES-ECB from nimcypher backs the wrap steps.
#
# (c) 2026 George Lemon | MIT License

import nimcypher/aes as cyAes
import nimcypher/hash as cyHash

import ./errors

const kwIv: array[8, byte] =
  [byte(0xA6), byte(0xA6), byte(0xA6), byte(0xA6),
   byte(0xA6), byte(0xA6), byte(0xA6), byte(0xA6)]

proc ecbBlock(key: openArray[byte], blk: openArray[byte],
              encrypt: bool): array[16, byte] =
  var blkArr: array[16, byte]
  for i in 0 ..< 16: blkArr[i] = blk[i]
  let output =
    if encrypt: cyAes.aesEcbEncrypt(key, blkArr, padded = false)
    else: cyAes.aesEcbDecrypt(key, blkArr, padded = false)
  for i in 0 ..< 16: result[i] = output[i]

proc checkSizes(kek, data: openArray[byte], wrapping: bool) =
  if kek.len notin [16, 24, 32]:
    joseFail("AES-KW KEK must be 128, 192, or 256 bits")
  if data.len < 16 or (data.len mod 8) != 0:
    joseFail("AES-KW key data must be a multiple of 64 bits >= 128 bits")
  if wrapping and data.len == 8:
    joseFail("AES-KW needs at least two 64-bit blocks")

proc aesKwWrap*(kek, keyData: openArray[byte]): seq[byte] =
  ## Wrap `keyData` with KEK `kek` (RFC 3394 §2.2.1).
  checkSizes(kek, keyData, true)
  let n = keyData.len div 8
  var a = kwIv
  var r = newSeq[array[8, byte]](n)
  for i in 0 ..< n:
    for j in 0 ..< 8: r[i][j] = keyData[i * 8 + j]
  var blk: array[16, byte]
  for j in 0 ..< 6:
    for i in 0 ..< n:
      for k in 0 ..< 8: blk[k] = a[k]
      for k in 0 ..< 8: blk[8 + k] = r[i][k]
      let b = ecbBlock(kek, blk, true)
      let t = uint64(n * j + i + 1)
      for k in 0 ..< 8:
        a[k] = b[k] xor byte((t shr (56 - 8 * k)) and 0xFF)
      for k in 0 ..< 8: r[i][k] = b[8 + k]
  result = newSeq[byte](8 + keyData.len)
  for k in 0 ..< 8: result[k] = a[k]
  for i in 0 ..< n:
    for k in 0 ..< 8: result[8 + i * 8 + k] = r[i][k]

proc aesKwUnwrap*(kek, wrapped: openArray[byte]): seq[byte] =
  ## Unwrap, raising JoseError when the integrity check fails.
  checkSizes(kek, wrapped, false)
  let n = wrapped.len div 8 - 1
  var a: array[8, byte]
  for k in 0 ..< 8: a[k] = wrapped[k]
  var r = newSeq[array[8, byte]](n)
  for i in 0 ..< n:
    for j in 0 ..< 8: r[i][j] = wrapped[8 + i * 8 + j]
  var blk: array[16, byte]
  for j in countdown(5, 0):
    for i in countdown(n - 1, 0):
      let t = uint64(n * j + i + 1)
      for k in 0 ..< 8:
        blk[k] = a[k] xor byte((t shr (56 - 8 * k)) and 0xFF)
      for k in 0 ..< 8: blk[8 + k] = r[i][k]
      let b = ecbBlock(kek, blk, false)
      for k in 0 ..< 8: a[k] = b[k]
      for k in 0 ..< 8: r[i][k] = b[8 + k]
  if not cyHash.verifyDigest(a, kwIv):
    joseFail("AES-KW integrity check failed")
  result = newSeq[byte](n * 8)
  for i in 0 ..< n:
    for k in 0 ..< 8: result[i * 8 + k] = r[i][k]
