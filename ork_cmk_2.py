from functions import *
from ed25519 import *
from secret_values import PRISM, gCMK, gR, gPass, username

############################ Private DB stored values ####################################
mSecOrki = 2627646718175798544208422319857993945837573553712688659812220622982826613173 
mgORKi = G * mSecOrki

userID = hash_str(username)
PRISMAuthi = hash_point_to_int((G * hash_point_to_int(gPass * PRISM)) * mSecOrki)

CMKi = 6725393821661916900898474909909757319036074513444465493423824022809330193183 # lagrange included. Add it to CMK2 then mod order to find out CMK
CMK2i = 339315406507158170149726732892616274206167571919710909833373306221787699688
PRISMi = 5541820989005081692604359973493053642643965593249633788119869624375982908663

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