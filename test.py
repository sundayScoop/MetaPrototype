import inspect
from functions import *
from ed25519 import *

a = G * 2

p = a.to_b64()

g = Point.from_b64(p)
print(a.x)
print(g.x)