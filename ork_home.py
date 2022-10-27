from secret_values import gCMK
from ork_cmk_1 import mgORKi as mgOrk1
from ork_cmk_2 import mgORKi as mgOrk2
from ork_cvk_1 import mgORKi as gvOrk1
from ork_cvk_2 import mgORKi as gvOrk2

def dns(userID):
    return (gCMK, (mgOrk1, mgOrk2))

def dnsCVK(userID):
    return (gvOrk1, gvOrk2)