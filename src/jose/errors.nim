# JOSE error type.
#
# (c) 2026 George Lemon | MIT License

type
  JoseError* = object of ValueError
    ## All errors raised by the jose package. Derives from ValueError so
    ## callers can catch either `JoseError` specifically or `ValueError`
    ## together with errors from the nimcypher layer.

template joseFail*(msg: string) =
  ## Raise a JoseError with the given message.
  raise newException(JoseError, msg)
