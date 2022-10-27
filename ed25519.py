


import base64


order = 7237005577332262213973186563042994240857116359379907606001950938285454250989
Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960

class Point:
    def __init__(self, x=None, y=None, a=-1, d=(-121665 * pow(121666, -1, 2**255 - 19)), m=(2**255 - 19)): # lower d is the mod_inv of 121666 for modulus m
        self.x: int = x
        self.y: int = y
        self.a = a ## Quick hack
        self.d = d
        self.m = m
    
    def encodePoint(self):
        point = self
        x_lsb = point.x & 1  # Correct
       

        y_b = bytearray(point.y.to_bytes(32, 'little'))
        

        if x_lsb == 1:
            mask = 128
            new_msb = y_b[31] | mask
        elif x_lsb == 0: 
            mask = 127
            new_msb = y_b[31] & mask

        y_b[31] = new_msb

        y_b = bytes(y_b)

        return y_b
    
    def __add__(self, other):
        new_point = Point()
        if isinstance(other, Point):
            new_point.x = ((self.x*other.y + self.y*other.x) * pow(1 + self.d*self.x*other.x*self.y*other.y, -1, self.m)) % self.m  ## https://bibliotecadigital.ipb.pt/bitstream/10198/24067/1/Nakai_Eduardo.pdf  I added finite fields here
            new_point.y = ((self.y*other.y - self.a*self.x*other.x) * pow(1 - self.d*self.x*other.x*self.y*other.y, -1, self.m)) % self.m # Point addition and doubling are the same for twisted edwards curves
            return new_point
    
    def __mul__(self, multiplier: int):
        new_point = Point()
        new_point.x = self.x
        new_point.y = self.y

        multiplier = list(bin(multiplier)[3:])

        for x_a in multiplier:
            new_point = new_point + new_point  #2P
            if x_a == '1':
                new_point = new_point + self  #P + G
        return new_point
    
    def to_b64(self):
        return base64.b64encode(self.x.to_bytes(32, 'little') + self.y.to_bytes(32, 'little')).decode()
    
    def from_b64(data):
        data = base64.b64decode(data)
        x = int.from_bytes(data[:32], 'little')
        y = int.from_bytes(data[32:], 'little')
        return Point(x, y)
    
    def from_hash(num: int):
        return Point(Gx, Gy) * num

    def isSafe(self) -> bool:
        if (self.x == 0 and self.y == 1) or ((self * order).x != 0):
            return False
        return True