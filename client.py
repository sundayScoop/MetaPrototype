from functions import *
from ed25519 import *
from ork_home import dns
from ork_cmk_1 import Convert as convert1
from ork_cmk_2 import Convert as convert2
from ork_cmk_1 import Authenticate as authenticate1
from ork_cmk_2 import Authenticate as authenticate2
import statistics

############################ Precondition ####################################
username = 'sundayScoop'
password = 'Password123'

################### Values to replicate sign up process ######################
userID = hash_str(username)

gPass = Point.from_hash(hash_str(password))


############################ Begin ##########################################
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