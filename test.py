import inspect
from functions import *
from ed25519 import *

x1 = 1
x2 = 2
secret = randNumber()
randCo = 530970117679225700845355356338959302532639881640020859155839157088983915029

def share(secret):
    l1 = (x2//(x2-x1))
    l2 = (x1//(x1-x2))

    return ((x1, (secret + randCo*x1) * l1 % order), (x2, (secret + randCo*x2) * l2 % order))

def interpolate(shares:tuple):
    l1 = (x2//(x2-x1))
    l2 = (x1//(x1-x2))

    return (shares[0][1] + shares[1][1]) % order

print(secret)
shares = share(secret)
print(shares)
print(interpolate(shares))