from operator import mod
from os import access
from functions import *
from ed25519 import *
from ork_home import dns
from ork_cmk_1 import Convert as convert1
from ork_cmk_2 import Convert as convert2
from ork_cmk_1 import ConvertCMK as convertcmk1
from ork_cmk_2 import ConvertCMK as convertcmk2
from ork_cmk_1 import Authenticate as authenticate1
from ork_cmk_2 import Authenticate as authenticate2
from ork_cmk_1 import AuthenticateCMK as authenticatecmk1
from ork_cmk_2 import AuthenticateCMK as authenticatecmk2
from ork_cvk_1 import SigninCVK as signin1
from ork_cvk_2 import SigninCVK as signin2
from vendor import GetChallenge, SignIn
import statistics

############################ Precondition ####################################
username = 'sundayScoop'
password = 'Password123'

################### Values to replicate sign up process ######################
userID = hash_str(username)

gPass = Point.from_hash(hash_str(password))


############################ PRISM ##########################################
challenge = GetChallenge()

startTimer = float(timestamp())

r1 = randNumber()
userID
gPass

gCMK, mgOrki = dns(userID)

response1 = convert1(userID, gPass * r1)
response2 = convert2(userID, gPass * r1)

gPassPRISM = ((response1[0] + response2[0]) * modInv(r1)) # Sum of gPassR * modInv (r1)

PRISMAuthi = (hash_point_to_int(mgOrki[0] * hash_point_to_int(gPassPRISM)), hash_point_to_int(mgOrki[1] * hash_point_to_int(gPassPRISM)))

d = ( aes_Decrypt(response1[1], key=PRISMAuthi[0]), aes_Decrypt(response2[1], PRISMAuthi[1]) )

VERIFY = ( hmac_sign(str(userID), d[0]['time'], d[0]['certTime'], key=PRISMAuthi[0]), hmac_sign(str(userID), d[1]['time'], d[1]['certTime'], key=PRISMAuthi[1]) )
deltaTime = statistics.median([float(d[0]['time']), float(d[1]['time'])])

ok = ( authenticate1(userID, d[0]['time'], d[0]['certTime'], VERIFY[0]), authenticate2(userID, d[1]['time'], d[1]['certTime'], VERIFY[1]) )

print(ok) ## Should see 2 OKs


######## TODO: Clean up static/secret variables

################### CMK #######################
assert(ok[0] == 'OK' and ok[1] == 'OK')

r2 = randNumber()
gUser = Point.from_hash(hash_str(str(userID), str(hash_point_to_int(challenge['gVVK'])))) # TODO: Change to hmac here

response1 = convertcmk1(userID, gPass * r2)
response2 = convertcmk2(userID, gPass * r2)

dd = ( aes_Decrypt(response1, key=PRISMAuthi[0]), aes_Decrypt(response2, key=PRISMAuthi[1]) )
gUserCMK = ( Point.from_b64(dd[0]['gPassR2CMK']) +  Point.from_b64(dd[1]['gPassR2CMK']) ) * modInv(r2)
CMKmul = first_32_bytes(hash_point_to_bytes(gUserCMK))

gCMKAuth = gCMK * CMKmul

SessKey = randNumber()

gSessKeyPub = G * SessKey

r3 = randNumber()

timestamp2 = (float(timestamp()) - startTimer) + deltaTime

gRmul = Point.from_b64(dd[0]['gR']) * r3

r4 = randNumber()

H_CMKmul_r4 = hash_str(gRmul.to_b64(), gCMKAuth.to_b64(), str(timestamp2), gSessKeyPub.to_b64()) * CMKmul * r4

r3r4 = r3 * r4

time = d[0]['time']
certTime = d[0]['certTime']

sig1 = authenticatecmk1(userID, aes_Encrypt(userID, time, certTime, H_CMKmul_r4, r3r4, key=PRISMAuthi[0]))

time = d[1]['time']
certTime = d[1]['certTime']
sig2 = authenticatecmk2(userID, aes_Encrypt(userID, time, certTime, H_CMKmul_r4, r3r4, key=PRISMAuthi[1]))

################# CVK ################################################

sigs = ( aes_Decrypt(sig1, key=PRISMAuthi[0]), aes_Decrypt(sig2, key=PRISMAuthi[1]))
S =  ( ( sigs[0]['S'] + sigs[1]['S'] ) * modInv(r4) ) % order
VUID = last_32_bytes(hash_point_to_bytes(gUserCMK)) 

cvkResponse = ( signin1(VUID, gRmul, S, timestamp2, gSessKeyPub, challenge), signin2(VUID, gRmul, S, timestamp2, gSessKeyPub, challenge) )

ECDH = ( hash_point_to_int(mgOrki[0] * SessKey), hash_point_to_int(mgOrki[1] * SessKey) )

f = ( aes_Decrypt(cvkResponse[0], key=ECDH[0]), aes_Decrypt(cvkResponse[1], key=ECDH[1]) )

gCVKR = Point.from_b64(f[0]['CVKR']) + Point.from_b64(f[1]['CVKR'])
CVKS = ( f[0]['CVKS'] + f[1]['CVKS'] ) % order

vendor_response = SignIn(VUID, gCVKR, CVKS, timestamp2, gSessKeyPub)

FINAL_ECDH = hash_point_to_int(challenge['gVVK'] * SessKey)

access_token = aes_Decrypt(vendor_response, key=FINAL_ECDH)

print(access_token)