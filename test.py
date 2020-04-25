# Dmytro Benedyk
# Feb 2020
# Thanks to Konstantin Nikolenko for help
#import requests
from serpent import _serpent
from serpent import serpent_cbc
import codecs

if __name__ == '__main__':
    print("####### ECB ENCRYPT/DECRYPT #########")
    ctx = _serpent(b"\xDE"*32)
    buff = ctx.encrypt(b"\xDE"*16)
    print(buff.hex())

    ctx = _serpent(b"\xDE"*32)
    print(ctx.decrypt(buff).hex())
    print("--------------------------------")
    print("####### СBC ENCRYPT/DECRYPT #1 #########")
    ctx = serpent_cbc(b"\x31\x32\x33\x34\x35\x36\x37\x38"+b"\0"*8, b"\0"*16) #if len = 8 we should add 8 zero bytes to the key (SERPENT key sizes: 128,192,256 bit)
    #buff = ctx.encrypt("abcdefghijklmnopqrstuvwxyz0123456789")
    buff = ctx.encrypt(b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39") #abcdefghijklmnopqrstuvwxyz0123456789
    print("Encrypted buffer:")
    print(buff.hex())

    ctx = serpent_cbc(b"\x31\x32\x33\x34\x35\x36\x37\x38"+b"\0"*8, b"\0"*16)
    buff = ctx.decrypt(buff)
    print("Decrypted buffer:")
    print(buff.hex())

    print("--------------------------------")
    print("####### СBC ENCRYPT/DECRYPT #2 #########")
    ctx = serpent_cbc(b"\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38", b"\0"*16) #if len = 8 we should add 8 zero bytes to the key (SERPENT key sizes: 128,192,256 bit)
    #buff = ctx.encrypt("abcdefghijklmnopqrstuvwxyz0123456789")
    buff = ctx.encrypt(b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39") #abcdefghijklmnopqrstuvwxyz0123456789
    print("Encrypted buffer:")
    print(buff.hex())

    ctx = serpent_cbc(b"\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38", b"\0"*16)
    buff = ctx.decrypt(buff)
    print("Decrypted buffer:")
    print(buff.hex())
