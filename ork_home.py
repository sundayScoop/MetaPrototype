from secret_values import gCMK
from ork_cmk_1 import mgORKi as mgOrk1
from ork_cmk_2 import mgORKi as mgOrk2


def dns(userID):
    return (gCMK, (mgOrk1, mgOrk2))