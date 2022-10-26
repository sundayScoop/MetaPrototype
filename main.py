from functions import *

from ed25519 import *

a = 'hey'
b = 'ho'

key = 100

sig = hmac_sign(a, b, key=key)

verif = hmac_verify(a, b, hashed=sig, key=key)
print(verif)