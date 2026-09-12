# Tests for AES-KW (RFC 3394), Concat-KDF + ECDH (RFC 7518 App. C),
# PBES2 (RFC 7518 4.8, RFC 7516 A.4).
#
# (c) 2026 George Lemon | MIT License

import std/strutils
import std/unittest

import jose/kw
import jose/kdf
import jose/jwk
import jose/b64
import jose/errors

import nimcypher/algos/ecdsa as ecdsaAlgo

proc hexBytes(s: string): seq[byte] =
  let h = s.replace(" ", "")
  result = newSeq[byte](h.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(h[2 * i .. 2 * i + 1]))

proc hexOf(data: openArray[byte]): string =
  for b in data: result.add(toHex(int(b), 2).toLowerAscii())

func sb(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

suite "aes-kw rfc3394":
  test "4.1 wrap 128-bit KEK":
    let kek = hexBytes("000102030405060708090A0B0C0D0E0F")
    let data = hexBytes("00112233445566778899AABBCCDDEEFF")
    check hexOf(aesKwWrap(kek, data)) ==
      "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"

  test "4.2 wrap 192-bit KEK":
    let kek = hexBytes("000102030405060708090A0B0C0D0E0F1011121314151617")
    let data = hexBytes("00112233445566778899AABBCCDDEEFF")
    check hexOf(aesKwWrap(kek, data)) ==
      "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"

  test "4.3 wrap 256-bit KEK":
    let kek = hexBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    let data = hexBytes("00112233445566778899AABBCCDDEEFF")
    check hexOf(aesKwWrap(kek, data)) ==
      "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"

  test "4.4/4.5 longer data roundtrips":
    let kek = hexBytes("000102030405060708090A0B0C0D0E0F")
    let data = hexBytes("00112233445566778899AABBCCDDEEFF0001020304050607")
    check aesKwUnwrap(kek, aesKwWrap(kek, data)) == data

  test "unwrap rejects tampered wrap":
    let kek = hexBytes("000102030405060708090A0B0C0D0E0F")
    let data = hexBytes("00112233445566778899AABBCCDDEEFF")
    var wrapped = aesKwWrap(kek, data)
    wrapped[^1] = wrapped[^1] xor 1
    expect(JoseError):
      discard aesKwUnwrap(kek, wrapped)

  test "unwrap rejects wrong KEK":
    let kek = hexBytes("000102030405060708090A0B0C0D0E0F")
    let other = hexBytes("000102030405060708090A0B0C0D0E00")
    let wrapped = aesKwWrap(kek, hexBytes("00112233445566778899AABBCCDDEEFF"))
    expect(JoseError):
      discard aesKwUnwrap(other, wrapped)

  test "rejects bad sizes":
    expect(JoseError):
      discard aesKwWrap(hexBytes("00112233"), hexBytes("00112233445566778899AABBCCDDEEFF"))
    expect(JoseError):
      discard aesKwWrap(hexBytes("000102030405060708090A0B0C0D0E0F"),
                        hexBytes("00112233"))

suite "concat-kdf rfc7518 app C":
  const z = [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131,
             191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72,
             246, 218, 167, 121, 140, 254, 144, 196]
  test "derives VqqN6vgjbSBcIijNcacQGg":
    var zb = newSeq[byte](32)
    for i in 0 ..< 32: zb[i] = byte(z[i])
    let derived = concatKdf(zb, 128, "A128GCM",
                            sb("Alice"), sb("Bob"))
    check b64urlEncode(derived) == "VqqN6vgjbSBcIijNcacQGg"

  test "ECDH Z matches Appendix C":
    let alice = jwkFromJsonStr(
      """{"kty":"EC","crv":"P-256",
          "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
          "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
          "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}""")
    let bob = jwkFromJsonStr(
      """{"kty":"EC","crv":"P-256",
          "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
          "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
          "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}""")
    let zAB = ecdsaAlgo.ecdh(alice.ecPriv, bob.ecPub)
    var expect = newSeq[byte](32)
    for i in 0 ..< 32: expect[i] = byte(z[i])
    check zAB == expect
    # and the other direction agrees
    check ecdsaAlgo.ecdh(bob.ecPriv, alice.ecPub) == expect

suite "pbes2":
  test "KEK matches openssl PBKDF2":
    # password "password", p2s 0011223344556677 ("ABEiM0RVZnc"),
    # p2c 1000, PBES2-HS256+A128KW. Reference:
    # openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt pass:password
    #   -kdfopt hexsalt:50424553322d48533235362b413132384b57000011223344556677
    #   -kdfopt iter:1000 PBKDF2
    let kek = pbes2Derive(sb("password"), "PBES2-HS256+A128KW",
                          b64urlDecode("ABEiM0RVZnc"), 1000, 256, 16)
    check hexOf(kek) == "e61caca8385d3ebc9bc1e232538cfe5a"

  test "roundtrip through AES-KW":
    let pw = sb("password")
    let p2s = b64urlDecode("ABEiM0RVZnc")
    let kek = pbes2Derive(pw, "PBES2-HS256+A128KW", p2s, 1000, 256, 16)
    let cek = hexBytes("00112233445566778899AABBCCDDEEFF")
    check aesKwUnwrap(kek, aesKwWrap(kek, cek)) == cek

  test "rejects low iteration count":
    expect(JoseError):
      discard pbes2Derive(sb("pw"), "PBES2-HS256+A128KW",
                          b64urlDecode("AAAAAAAAAAAAAAAAAAAAAA"), 999, 256, 16)
