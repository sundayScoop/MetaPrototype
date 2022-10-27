import hashlib
import ed25519
import hmac
from Cryptodome.Cipher import AES
import json
import random
import inspect
import time
from cryptography.fernet import Fernet
import base64


############################# Hashing ############################################ 
'''
USAGE FOR HMAC

a = 'hey'
b = 'ho'

key = 100

sig = hmac_sign(a, b, key=key)

verif = hmac_verify(a, b, hashed=sig, key=key)
print(verif)

True
'''
def hmac_sign(*args, key: int) -> bytes:
    data: bytes = args[0].encode()
    for arg in args[1:]:
        if(type(arg) == 'str'):
            data += arg.encode()
        elif(type(arg) == 'bytes'):
            data += arg

    hmac_obj = hmac.new(key=key.to_bytes(32, 'little'), msg=data, digestmod=hashlib.sha256)
    return hmac_obj.digest()

def hmac_verify(*args: str, hashed: bytes, key: int) -> bool:
    data: bytes = args[0].encode()
    for arg in args[1:]:
        if(type(arg) == 'str'):
            data += arg.encode()
        elif(type(arg) == 'bytes'):
            data += arg

    hmac_obj = hmac.new(key=key.to_bytes(32, 'little'), msg=data, digestmod=hashlib.sha256)
    return hmac_obj.digest() == hashed

def hash_point_to_bytes(point: ed25519.Point) -> bytes:
    return hashlib.sha512(point.x.to_bytes(32, 'little') + point.y.to_bytes(32, 'little')).digest()

def hash_point_to_int(point: ed25519.Point) -> int:
    return int.from_bytes(hashlib.sha512(point.x.to_bytes(32, 'little') + point.y.to_bytes(32, 'little')).digest(), 'little') % ed25519.order 

def hash_str(*args: str) -> int:
    data = ''
    for arg in args:
        data += arg
    return int.from_bytes(hashlib.sha512(data.encode()).digest(), 'little') % ed25519.order

############################## AES ################################################
'''
USAGE

Key must be int
Arguments can be anything!
___________________________

key = 100
cmk = 10839034783

encrypted = aes_Encrypt(cmk, key=key)

decrypted = aes_Decrypt(encrypted, key=key)

print(decrypted['cmk'])

10839034783

----------------------------------------
It can also accept multiple arguments

key = 100
cmk = 10839034783
cvk = 19497638754

encrypted = aes_Encrypt(cmk, cvk, key=key)

print(encrypted)

decrypted = aes_Decrypt(encrypted, key=key)

print(decrypted['cmk'])
print(decrypted['cvk'])

10839034783
19497638754
'''

def aes_Encrypt(*args, key: int) -> tuple:
    d = {}
    for arg in args:
        d[retrieve_name(arg)[0]] = arg  # <- Awesome!

    key = base64.b64encode(key.to_bytes(32, 'little'))

    if ('certTime' in d):
        d['certTime'] = to_base64(d['certTime'])
    data = json.dumps(d)
    f = Fernet(key)
    ciphertext = f.encrypt(data.encode())
    return ciphertext

def aes_Decrypt(ciphertext, key: int) -> dict:
    key = base64.b64encode(key.to_bytes(32, 'little'))
    f = Fernet(key)
    decrypted = f.decrypt(ciphertext)
    d = json.loads(decrypted.decode())
    if ('certTime' in d):
        d['certTime'] = from_base64(d['certTime'])
    return d

############################## Math ################################################
def modInv(num: int) -> int:
    return pow(num, -1, ed25519.order)

def randNumber() -> int:
    return random.randint(0, ed25519.order)

############################## Byte operations ################################################
def num_from_bytes(num: bytes) -> int:
    return int.from_bytes(num, 'little') % ed25519.order

def first_32_bytes(data: bytes) -> int:
    return int.from_bytes(data[:32], 'little') % ed25519.order

def last_32_bytes(data :bytes) -> int:
    return int.from_bytes(data[32:], 'little') % ed25519.order

#############################################################################################


def to_base64(data: bytes):
    return base64.b64encode(data).decode()

def from_base64(data: str):
    return base64.b64decode(data)

def timestamp() -> str:
    return str(time.time())

def retrieve_name(var):
    callers_local_vars = inspect.currentframe().f_back.f_back.f_locals.items()
    return [var_name for var_name, var_val in callers_local_vars if var_val is var]

G = ed25519.Point(ed25519.Gx, ed25519.Gy)