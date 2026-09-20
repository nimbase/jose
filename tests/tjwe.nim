# Tests for JWE compact serialization (RFC 7516 App. A, RFC 8037 A.6).
#
# (c) 2026 George Lemon | MIT License

import std/json
import std/strutils
import std/unittest

import nimcypher/algos/x25519 as x25519Algo

import ../src/jose/jwk
import ../src/jose/jwe
import ../src/jose/algs
import ../src/jose/b64
import ../src/jose/errors

const imagination =
  "The true sign of intelligence is not knowledge but imagination."

const rsaKeyA1 = """{"n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw","e":"AQAB","d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ","p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0","q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc","dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE","dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis","qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY","kty":"RSA"}"""
const rsaKeyA2 = """{"n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw","e":"AQAB","d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ","p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM","q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0","dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs","dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU","qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo","kty":"RSA"}"""

const jweA1 = # RSA-OAEP / A256GCM (RFC 7516 A.1)
  "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ." &
  "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe" &
  "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb" &
  "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV" &
  "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8" &
  "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi" &
  "6UklfCpIMfIjf7iGdXKHzg." &
  "48V1_ALb6US04U3b." &
  "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji" &
  "SdiwkIr3ajwQzaBtQD_A." &
  "XFBoMYUZodetZdvTiFvSkQ"

const jweA2 = # RSA1_5 / A128CBC-HS256 (RFC 7516 A.2)
  "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." &
  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm" &
  "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc" &
  "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF" &
  "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8" &
  "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv" &
  "-B3oWh2TbqmScqXMR4gp_A." &
  "AxY8DCtDaGlsbGljb3RoZQ." &
  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." &
  "9hH0vgRfYgPnAHOd8stkvw"

const jweA3 = # A128KW / A128CBC-HS256 (RFC 7516 A.3)
  "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." &
  "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." &
  "AxY8DCtDaGlsbGljb3RoZQ." &
  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." &
  "U0m_YmjN04DJvceFICbCVQ"

const octA3 = """{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"""

const bobP256 = """{"kty":"EC","crv":"P-256",
  "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
  "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
  "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"""

func sb(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

suite "jwe rfc7516 vectors":
  test "A.1 RSA-OAEP/A256GCM decrypts":
    let key = jwkFromJsonStr(rsaKeyA1)
    check key.hasPrivate and key.rsaCrt
    let d = jweDecrypt(jweA1, key)
    check d.header["alg"].getStr() == "RSA-OAEP"
    check d.header["enc"].getStr() == "A256GCM"
    check jweDecryptStr(jweA1, key) == imagination

  test "A.2 RSA1_5/A128CBC-HS256 decrypts":
    # NOTE: A.2/A.3 plaintext is "Live long and prosper." (same CEK as
    # Appendix B); only A.1 uses the imagination sentence.
    let key = jwkFromJsonStr(rsaKeyA2)
    check jweDecryptStr(jweA2, key) == "Live long and prosper."

  test "A.3 A128KW/A128CBC-HS256 decrypts":
    let key = jwkFromJsonStr(octA3)
    check jweDecryptStr(jweA3, key) == "Live long and prosper."

  test "A.2 and A.3 share IV/ciphertext (same CEK)":
    let a2 = jweA2.split('.')
    let a3 = jweA3.split('.')
    check a2[2] == a3[2]
    check a2[3] == a3[3]

suite "jwe x25519 rfc8037 A.6":
  test "Z matches the RFC value":
    # eph priv 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    # Bob pub de9edb7b7b7dc1b4d35b61c2ece43537f8343c85b78674dadfc7e146f882b4f
    var ephSeed, bobPub: array[32, byte]
    let ephHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    let bobHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    for i in 0 ..< 32:
      ephSeed[i] = byte(parseHexInt(ephHex[2 * i .. 2 * i + 1]))
      bobPub[i] = byte(parseHexInt(bobHex[2 * i .. 2 * i + 1]))
    let z = x25519Algo.x25519(ephSeed, bobPub)
    var expect: array[32, byte]
    let zHex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    for i in 0 ..< 32:
      expect[i] = byte(parseHexInt(zHex[2 * i .. 2 * i + 1]))
    check z == expect

suite "jwe roundtrips":
  proc rt(alg: JweAlg, enc: JweEnc, key: Jwk, msg = imagination,
          p2c = 1000): string =
    let tok = jweEncrypt(alg, enc, key, sb(msg),
                         p2c = p2c)
    check jweDecryptStr(tok, key) == msg
    tok

  test "dir across all enc":
    for enc in [A128CBC_HS256, A192CBC_HS384, A256CBC_HS512,
                A128GCM, A192GCM, A256GCM, C20P]:
      let key = jwkOctGenerate(case enc
        of A128CBC_HS256: 256
        of A192CBC_HS384: 384
        of A256CBC_HS512: 512
        of A128GCM: 128
        of A192GCM: 192
        of A256GCM: 256
        else: 256)
      discard rt(Dir, enc, key)

  test "A128KW/A192KW/A256KW x CBC/GCM":
    for (alg, bits) in [(A128KW, 128), (A192KW, 192),
                        (A256KW, 256)]:
      let kek = jwkOctGenerate(bits)
      for enc in [A128CBC_HS256, A128GCM, A256GCM, C20P]:
        discard rt(alg, enc, kek)

  test "RSA-OAEP/RSA-OAEP-256/RSA1_5 x CBC/GCM":
    let priv = jwkFromJsonStr(rsaKeyA1)
    for alg in [RSA_OAEP, RSA_OAEP_256, RSA1_5]:
      for enc in [A128CBC_HS256, A256GCM]:
        discard rt(alg, enc, priv)

  test "ECDH-ES direct + wrap (P-256, X25519)":
    let bobEc = jwkFromJsonStr(bobP256)
    let bobX = jwkX25519Generate()
    for key in [bobEc, bobX]:
      for alg in [ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A256KW]:
        for enc in [A128CBC_HS256, A128GCM]:
          let tok = jweEncrypt(alg, enc, key, sb(imagination))
          check jweDecryptStr(tok, key) == imagination
          # epk present, encrypted key empty iff direct
          let hdr = jweDecrypt(tok, key).header
          check hdr.hasKey("epk")
          check (tok.split('.')[1].len == 0) == (alg == ECDH_ES)

  test "PBES2 all three PRFs":
    let pw = jwkOctKey(sb("correct horse battery staple"))
    for alg in [PBES2_HS256_A128KW, PBES2_HS384_A192KW,
                PBES2_HS512_A256KW]:
      discard rt(alg, A128GCM, pw)

  test "PBES2 accepts short passwords via jwkPassword":
    let pw = jwkPassword(sb("pw"))
    let tok = jweEncrypt(PBES2_HS256_A128KW, A128GCM, pw,
                         sb(imagination), p2c = 1000)
    check jweDecryptStr(tok, pw) == imagination

  test "apu/apv flow into KDF":
    let bobEc = jwkFromJsonStr(bobP256)
    let tok = jweEncrypt(ECDH_ES, A128GCM, bobEc, sb(imagination),
                         apu = sb("Alice"), apv = sb("Bob"))
    let hdr = jweDecrypt(tok, bobEc).header
    check hdr["apu"].getStr() == "QWxpY2U"
    check hdr["apv"].getStr() == "Qm9i"
    check jweDecryptStr(tok, bobEc) == imagination

  test "kid flows into header":
    let kek = jwkOctGenerate(128, kid = "wrap-1")
    let tok = jweEncrypt(A128KW, A128GCM, kek, sb("x"))
    check jweDecrypt(tok, kek).header["kid"].getStr() == "wrap-1"

suite "jwe rejection":
  test "tampered ciphertext fails (GCM)":
    let key = jwkFromJsonStr(octA3)
    let tok = jweEncrypt(A128KW, A128GCM, key, sb(imagination))
    var parts = tok.split('.')
    var ct = b64urlDecode(parts[3])
    ct[0] = ct[0] xor 1
    parts[3] = b64urlEncode(ct)
    expect(JoseError):
      discard jweDecrypt(parts.join("."), key)

  test "tampered tag fails (CBC-HMAC)":
    let key = jwkFromJsonStr(octA3)
    let tok = jweEncrypt(A128KW, A128CBC_HS256, key, sb(imagination))
    var parts = tok.split('.')
    var tag = b64urlDecode(parts[4])
    tag[^1] = tag[^1] xor 1
    parts[4] = b64urlEncode(tag)
    expect(JoseError):
      discard jweDecrypt(parts.join("."), key)

  test "tampered protected header fails":
    let key = jwkFromJsonStr(octA3)
    let tok = jweEncrypt(A128KW, A128GCM, key, sb(imagination))
    var parts = tok.split('.')
    parts[0] = if parts[0][0] == 'A': 'B' & parts[0][1 .. ^1]
               else: 'A' & parts[0][1 .. ^1]
    expect(JoseError):
      discard jweDecrypt(parts.join("."), key)

  test "tampered encrypted key fails":
    let priv = jwkFromJsonStr(rsaKeyA1)
    let tok = jweEncrypt(RSA_OAEP, A128GCM, priv, sb(imagination))
    var parts = tok.split('.')
    var ek = b64urlDecode(parts[1])
    ek[^1] = ek[^1] xor 1
    parts[1] = b64urlEncode(ek)
    expect(JoseError):
      discard jweDecrypt(parts.join("."), priv)

  test "wrong key fails":
    let key = jwkFromJsonStr(octA3)
    let other = jwkOctGenerate(128)
    let tok = jweEncrypt(A128KW, A128GCM, key, sb(imagination))
    expect(JoseError):
      discard jweDecrypt(tok, other)

  test "dir rejects wrong-size key":
    let key = jwkOctGenerate(128)
    expect(JoseError):
      discard jweEncrypt(Dir, A256GCM, key, sb("x"))

  test "RSA-OAEP refuses EC key":
    let ec = jwkFromJsonStr(bobP256)
    expect(JoseError):
      discard jweEncrypt(RSA_OAEP, A128GCM, ec, sb("x"))

  test "allowAlgs/allowEncs restrict":
    let key = jwkFromJsonStr(octA3)
    let tok = jweEncrypt(A128KW, A128GCM, key, sb(imagination))
    expect(JoseError):
      discard jweDecrypt(tok, key, allowAlgs = [RSA_OAEP])
    expect(JoseError):
      discard jweDecrypt(tok, key, allowEncs = [A256GCM])
    check jweDecryptStr(tok, key, allowAlgs = [A128KW],
                        allowEncs = [A128GCM]) == imagination

  test "zip rejected":
    let key = jwkFromJsonStr(octA3)
    let tok = jweEncrypt(A128KW, A128GCM, key, sb("x"))
    var parts = tok.split('.')
    let hdr = parseJson(b64urlDecodeStr(parts[0]))
    hdr["zip"] = %"DEF"
    parts[0] = b64urlEncode($hdr)
    expect(JoseError):
      discard jweDecrypt(parts.join("."), key)

  test "A128GCMKW rejected as unsupported":
    let key = jwkOctGenerate(128)
    expect(JoseError):
      discard jweEncrypt(A128GCMKW, A128GCM, key, sb("x"))

  test "malformed tokens rejected":
    let key = jwkFromJsonStr(octA3)
    for bad in ["", "a.b.c.d", "a.b.c.d.e.f", "...."]:
      expect(JoseError):
        discard jweDecrypt(bad, key)
