
from os import access
from functions import aes_Encrypt, hash_point_to_int, hash_str, G
from secret_values import VVK, gVVK, gCVK
from ed25519 import Point

challenge = 'Find girlfriend'
access_token = 'LOGGED IN'

def GetChallenge():
    return { "challenge": challenge, "gVVK": gVVK }

def SignIn(VUID, gCVKR: Point, CVKS, timestamp2, gSessKeyPub: Point):
    # Retirve gCVK from record
    H = hash_str(gCVKR.to_b64(), gCVK.to_b64(), str(timestamp2), gSessKeyPub.to_b64(), str(VUID), str(challenge))
    ECDH = hash_point_to_int(gSessKeyPub * VVK)
    assert(G * 8 * CVKS == gCVKR * 8 + gCVK * H)
    return aes_Encrypt(access_token, key=ECDH)