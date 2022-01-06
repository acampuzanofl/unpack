import os,sys
import struct

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def sha(initVal):

    sha_object = [0] * 0x55
    sha_constants = [0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0]

    sha_object[0x50] = sha_constants[0]
    sha_object[0x51] = sha_constants[1]
    sha_object[0x52] = sha_constants[2]
    sha_object[0x53] = sha_constants[3]
    sha_object[0x54] = sha_constants[4]

    for i in range(len(initVal)):
        sha_object[i] = initVal[i]

    sha_object[i+1] = struct.unpack("I", b'\x80\x00\x00\x00')[0]

    size = len(initVal) * 4 * 8
    sha_object[15] = struct.unpack(">I",struct.pack("I",size))[0]  

    offset = 2
    for i in range(0x40):
        temp = sha_object[offset + 0xb]
        offset += 1
        temp ^= sha_object[offset + 0x5]
        temp ^= sha_object[offset - 0x3]
        temp ^= sha_object[offset - 0x1]
        temp = rol(temp, 1, 32)
        sha_object[offset + 0xd] = temp

    for i in range(0x50):
        a = sha_object[0x50] & 0xFFFFFFFF
        b = sha_object[0x51] & 0xFFFFFFFF
        c = sha_object[0x52] & 0xFFFFFFFF
        d = sha_object[0x53] & 0xFFFFFFFF
        e = sha_object[0x54] & 0xFFFFFFFF

        sha_object[0x52] = rol(b, 0x1e, 32)
        sha_object[0x51] = a
        sha_object[0x53] = c
        sha_object[0x54] = d

        if i < 0x14:
            b = ~b & d | c & b

        elif i < 0x28 or 0x3b < i:
            b = d ^ c ^ b

        else:
            b = (c | b) & d | c & b
        
        e = e + rol(a, 5, 32) + b + sha_object[i]
        if i < 0x14:
            e = e + 0x5a827999
        
        elif i < 0x28:
            e = e + 0x6ed9eba1
        
        elif i < 0x3c:
            e = e + 0x8f1bbcdc
        
        else:
            e = e + 0xca62c1d6

        sha_object[0x50] = e & 0xFFFFFFFF

        b = a
        a = e
        d = c
    return sha_object

fileName = sys.argv[1]

try:
    if os.path.exists(fileName):
        with open(fileName, mode="rb") as file:
            fileContent = file.read()
            fileSize = len(fileContent)
        print("size of {0}: {1}".format(os.path.basename(fileName),hex(fileSize)))
except:
    print("could not read file")

fileSize = [fileSize] * 1
sha_object = sha(fileSize)

buf = [0] * 6
salt = [0] * 0x40001
buf[0] = sha_object[0x50]   
buf[1] = sha_object[0x51]
buf[2] = sha_object[0x52]
buf[3] = sha_object[0x53]
buf[4] = sha_object[0x54]
for i in range(0, 0x40000, 5):
    buf[5] +=  1
    sha_object = sha(buf)

    salt[i + 0] = sha_object[0x50]   
    salt[i + 1] = sha_object[0x51]
    salt[i + 2] = sha_object[0x52]
    salt[i + 3] = sha_object[0x53]
    salt[i + 4] = sha_object[0x54]







