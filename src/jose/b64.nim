# Base64url encoding without padding (RFC 7515 section 2).
#
# (c) 2026 George Lemon | MIT License

import std/base64

import ./errors

proc b64urlEncode*(data: openArray[byte]): string =
  ## Encode bytes as base64url with padding stripped.
  result = base64.encode(data, safe = true)
  let pad = result.find('=')
  if pad >= 0:
    result.setLen(pad)

proc b64urlEncode*(s: string): string =
  ## Encode a string as base64url with padding stripped.
  b64urlEncode(s.toOpenArrayByte(0, s.len - 1))

proc b64urlDecode*(s: string): seq[byte] =
  ## Decode unpadded base64url to bytes. Raises JoseError on bad input.
  for c in s:
    if c notin {'A'..'Z', 'a'..'z', '0'..'9', '-', '_'}:
      joseFail("invalid base64url character")
  if s.len mod 4 == 1:
    joseFail("invalid base64url length")
  var padded = s
  case s.len mod 4
  of 2: padded.add("==")
  of 3: padded.add("=")
  else: discard
  try:
    let decoded = base64.decode(padded)
    result = newSeq[byte](decoded.len)
    for i in 0 ..< decoded.len:
      result[i] = byte(decoded[i])
  except ValueError:
    joseFail("invalid base64url encoding")

proc b64urlDecodeStr*(s: string): string =
  ## Decode unpadded base64url to a string. Raises JoseError on bad input.
  let bytes = b64urlDecode(s)
  result = newString(bytes.len)
  for i in 0 ..< bytes.len:
    result[i] = char(bytes[i])

proc b64urlEncodeInt*(v: openArray[byte]): string =
  ## Encode a base64urlUInt (RFC 7518 section 2): leading zero octets
  ## stripped, with the value zero encoded as a single 0x00 octet.
  var start = 0
  while start < v.len and v[start] == 0:
    inc start
  if start == v.len:
    return b64urlEncode([byte(0)])
  b64urlEncode(v.toOpenArray(start, v.len - 1))
