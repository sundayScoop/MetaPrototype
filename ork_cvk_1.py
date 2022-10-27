from functions import *
from ed25519 import *
from secret_values import gCVK, gCVKR, gCMKAuth, VUID


############################ Private DB stored values ####################################

mSecOrki = 6107715663567468914686592078826594155354841482986702310262172706871589260875
mgORKi = G * mSecOrki

CVKi = 3208725611770704962247767548273607028120806772600484944577389363838827555904
CVK2i = 7134961840108934091324384251228910097794298865223011380805184528515902519738

VUID
gCVK
gCVKR
gCMKAuth

#########################################################################################

def SigninCVK(VUID, gRMul: Point, S, timestamp2, gSessKeyPub: Point, challenge):
    # Retirve CVk record
    assert(float(timestamp()) - timestamp2 < 10.0)
    H = (hash_str(gRMul.to_b64(), gCMKAuth.to_b64(), str(timestamp2), gSessKeyPub.to_b64())) * hash_str("CMK Authentication") ##### ERROR IS HERE
    assert(G * 8 * S == gRMul * 8 + gCMKAuth * H * 8)
    CVKR = (G * CVK2i).to_b64()
    CVKH = hash_str(gCVKR.to_b64(), gCVK.to_b64(), str(timestamp2), gSessKeyPub.to_b64(), str(VUID), str(challenge) )
    CVKS = ( CVK2i + CVKH * CVKi ) % order
    ECDH = hash_point_to_int(gSessKeyPub * mSecOrki)

    return aes_Encrypt(CVKR, CVKS, key=ECDH)

