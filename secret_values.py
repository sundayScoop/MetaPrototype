from functions import *
from ed25519 import Point


CMK = 6686677097644156125357187503498312557612878442035308000268399539583610478737
CMK2 = 5835749935466652642132749117472459361585669024180154977856899317885698721243
PRISM = 633244352968729119678115876872021993147871002850232099570402999731503512268

CVK = 1073392688206126780278528417797844211527763504660221613132855524830429862923
CVK2 = 3036510802375241344816836769275495746364509550971484831246753107168967344840

#####
VVK = 5681229507111534773208062300262925403567973615778712709275652355476077461093
gVVK = G * VVK


username = 'sundayScoop'
password = 'Password123'
gPass = Point.from_hash(hash_str(password))
userID = hash_str(username)
gUser = Point.from_hash(hash_str(str(userID), str(hash_point_to_int(gVVK))))


#### Not so secret, but secret for some ppl #####
VUID = last_32_bytes(hash_point_to_bytes(gUser * CMK))
gCVK = G * CVK
gCVKR = G * CVK2
print("DICK "  + gCVKR.to_b64())

CMKmul = first_32_bytes(hash_point_to_bytes(gUser * CMK))

gCMKAuth = (G * CMK) * CMKmul

gCMK = G * CMK
gR = G * CMK2

