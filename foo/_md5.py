import ffi
import sys


_h = None

def get():
    global _h
    if _h:
        return _h
    err = None
    try:
        _h = ffi.open('libmd5.so')
        return _h
    except OSError as e:
        err = e
    raise err

_md5 = get()
md5 = _md5.func("s", "md5", "s")
