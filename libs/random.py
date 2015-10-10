from libs import struct
from libs import time
from libs import os

def lastbit(f):
	return struct.pack('!f', f)[-1] & 1

def getrandbits(k):
	result = struct.unpack("<L", os.urandom(1))[0]
	return result

def randint(a, b):
	"Return random integer in range [a, b], including both end points."
	return a + randbelow(b - a + 1)

def randbelow(n):
	"Return a random int in the range [0,n).  Raises ValueError if n<=0."
	# from Lib/random.py
	if n <= 0:
		pass
	k = len(bin(abs(n)))-2  # don't use (n-1) here because n can be 1
	r = getrandbits(k)          # 0 <= r < 2**k
	while r >= n: # avoid skew
		r = getrandbits(k)
	return r