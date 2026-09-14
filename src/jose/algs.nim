# Algorithm identifiers (RFC 7518): JWS `alg`, JWE `alg` and `enc`.
#
# String-valued enums, so `$alg` is the JOSE wire string, e.g.
# `$A128GCM == "A128GCM"`. Identifiers that would contain `-`, `+`
# or start lowercase on the wire use `_` aliases, e.g.
# `RSA_OAEP == "RSA-OAEP"`, `Dir == "dir"`.
#
# (c) 2026 George Lemon | MIT License

import ./errors

type
  JwsAlg* = enum
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    ES256K = "ES256K"
    EdDSA = "EdDSA"

  JweAlg* = enum
    Dir = "dir"
    A128KW = "A128KW"
    A192KW = "A192KW"
    A256KW = "A256KW"
    RSA_OAEP = "RSA-OAEP"
    RSA_OAEP_256 = "RSA-OAEP-256"
    RSA1_5 = "RSA1_5"
    ECDH_ES = "ECDH-ES"
    ECDH_ES_A128KW = "ECDH-ES+A128KW"
    ECDH_ES_A192KW = "ECDH-ES+A192KW"
    ECDH_ES_A256KW = "ECDH-ES+A256KW"
    PBES2_HS256_A128KW = "PBES2-HS256+A128KW"
    PBES2_HS384_A192KW = "PBES2-HS384+A192KW"
    PBES2_HS512_A256KW = "PBES2-HS512+A256KW"
    A128GCMKW = "A128GCMKW"
    A192GCMKW = "A192GCMKW"
    A256GCMKW = "A256GCMKW"

  JweEnc* = enum
    A128CBC_HS256 = "A128CBC-HS256"
    A192CBC_HS384 = "A192CBC-HS384"
    A256CBC_HS512 = "A256CBC-HS512"
    A128GCM = "A128GCM"
    A192GCM = "A192GCM"
    A256GCM = "A256GCM"
    C20P = "C20P"

proc parseJwsAlg*(s: string): JwsAlg =
  ## Parse a JWS `alg` wire string. Raises JoseError when unknown.
  case s
  of "HS256": HS256
  of "HS384": HS384
  of "HS512": HS512
  of "RS256": RS256
  of "RS384": RS384
  of "RS512": RS512
  of "PS256": PS256
  of "PS384": PS384
  of "PS512": PS512
  of "ES256": ES256
  of "ES384": ES384
  of "ES512": ES512
  of "ES256K": ES256K
  of "EdDSA": EdDSA
  else: joseFail("unsupported JWS alg: " & s)

proc parseJweAlg*(s: string): JweAlg =
  ## Parse a JWE `alg` wire string. Raises JoseError when unknown.
  case s
  of "dir": Dir
  of "A128KW": A128KW
  of "A192KW": A192KW
  of "A256KW": A256KW
  of "RSA-OAEP": RSA_OAEP
  of "RSA-OAEP-256": RSA_OAEP_256
  of "RSA1_5": RSA1_5
  of "ECDH-ES": ECDH_ES
  of "ECDH-ES+A128KW": ECDH_ES_A128KW
  of "ECDH-ES+A192KW": ECDH_ES_A192KW
  of "ECDH-ES+A256KW": ECDH_ES_A256KW
  of "PBES2-HS256+A128KW": PBES2_HS256_A128KW
  of "PBES2-HS384+A192KW": PBES2_HS384_A192KW
  of "PBES2-HS512+A256KW": PBES2_HS512_A256KW
  of "A128GCMKW": A128GCMKW
  of "A192GCMKW": A192GCMKW
  of "A256GCMKW": A256GCMKW
  else: joseFail("unsupported JWE alg: " & s)

proc parseJweEnc*(s: string): JweEnc =
  ## Parse a JWE `enc` wire string. Raises JoseError when unknown.
  case s
  of "A128CBC-HS256": A128CBC_HS256
  of "A192CBC-HS384": A192CBC_HS384
  of "A256CBC-HS512": A256CBC_HS512
  of "A128GCM": A128GCM
  of "A192GCM": A192GCM
  of "A256GCM": A256GCM
  of "C20P": C20P
  else: joseFail("unsupported JWE enc: " & s)
