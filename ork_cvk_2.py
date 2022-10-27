from functions import *
from ed25519 import *
from secret_values import gCVK, gCVKR, gCMKAuth, VUID


############################ Private DB stored values ####################################

mSecOrki = 1366720665161724309527985978467876155880756244784685579081929735709425230280
mgORKi = G * mSecOrki

CVKi = 5101672653767684032003947432567231424264073091439644274557417099277056558008
CVK2i = 3138554539598569467465639081089579889427327045128381056443519516938519076091

VUID
gCVK
gCVKR
gCMKAuth
gCMKAuth

def SigninCVK(VUID, gRMul: Point, S, timestamp2, gSessKeyPub: Point, challenge):
    # Retirve CVk record
    assert(float(timestamp()) - timestamp2 < 10.0)
    H = (hash_str(gRMul.to_b64(), gCMKAuth.to_b64(), str(timestamp2), gSessKeyPub.to_b64())) * hash_str("CMK Authentication") ##### ERROR IS HERE
    assert((G * 8 * S).x == (gRMul * 8 + gCMKAuth * H * 8).x)
    CVKR = (G * CVK2i).to_b64()
    CVKH = hash_str(gCVKR.to_b64(), gCVK.to_b64(), str(timestamp2), gSessKeyPub.to_b64(), str(VUID), str(challenge) )
    CVKS = ( CVK2i + CVKH * CVKi ) % order
    ECDH = hash_point_to_int(gSessKeyPub * mSecOrki)

    return aes_Encrypt(CVKR, CVKS, key=ECDH)