import gc
from re import purge
from functions import *
from ed25519 import *
from secret_values import PRISM, gCMK, gR, gPass, username

############################ Private DB stored values ####################################
mSecOrki = 1345646718175798544208422319857993945837573553712688659812220622982826613200 
mgORKi = G * mSecOrki

userID = hash_str(username)
PRISMAuthi = hash_point_to_int((G * hash_point_to_int(gPass * PRISM)) * mSecOrki)

CMKi = 7198288853314501438431899156631549479433920287970750112846526455059734536543 # lagrange included. Add it to CMK2 then mod order to find out CMK
CMK2i = 5496434528959494471983022384579843087379501452260444068023526011663911021555
PRISMi = 2328428941295909641046942466421962591361021768980505917452484313640974854594

gCMK
gR

#########################################################################################
def Convert(userID, gPassR1: Point):
    # Retrive CMK record
    assert(gPassR1.isSafe())
    time = timestamp()
    purpose = 'auth'
    certTime = hmac_sign(time, str(userID), purpose, key=mSecOrki)
    return (gPassR1 * PRISMi, aes_Encrypt(time, certTime, key=PRISMAuthi))

def Authenticate(userID, time, certTime, VERIFY):
    if hmac_verify(str(userID), time, certTime, hashed=VERIFY, key=PRISMAuthi):
        return 'OK'
    else:
        return 'NOT OK'

def getGR():
    return gR

def getGCMK():
    return gCMK

def ConvertCMK(userID, gUserR2: Point):
    # Retrieve CMK record
    assert(gUserR2.isSafe())
    gUserR2CMK = (gUserR2 * CMKi).to_b64()
    gR = getGR().to_b64()
    gCMK = getGCMK().to_b64()
    return aes_Encrypt(gUserR2CMK, gR, gCMK, key=PRISMAuthi)

def AuthenticateCMK(userID, data):
    # Retirve CMk record
    d = aes_Decrypt(data, key=PRISMAuthi)
    purpose = 'auth'

    assert(hmac_verify(str(d['time']), str(userID), purpose, hashed=d['certTime'], key=mSecOrki))

    blindH = d['H_CMKmul_r4'] * hash_str("CMK Authentication")
    S = ( CMK2i * d['r3r4'] + blindH * CMKi ) % order

    return aes_Encrypt(S, key=PRISMAuthi)