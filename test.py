# Dmytro Benedyk
# Feb 2020
# Thanks to Konstantin Nikolenko for help
#import requests
from serpent import _serpent
from serpent import serpent_cbc
import codecs

if __name__ == '__main__':
    print("####### ECB ENCRYPT/DECRYPT #########")
    key = b"\xFF"*32
    ctx = _serpent(key)
    print ('key = ' + key.hex())
    plaintext = b"\xDE"*16
    buff = ctx.encrypt(plaintext)
    print("Encrypted buffer:")
    print(buff.hex())
    ctx = _serpent(key)
    print("Decrypted buffer:")
    print(ctx.decrypt(buff).hex())
    print("--------------------------------")
    print("####### СBC ENCRYPT/DECRYPT #1 #########")
    key = b"\x31\x32\x33\x34\x35\x36\x37\x38"+b"\0"*8  #if len = 8 we should add 8 zero bytes to the key (SERPENT key sizes: 128,192,256 bit)
    iv = b"\0" * 16
    print('key = ' + key.hex())
    print('iv = ' + iv.hex())
    ctx = serpent_cbc(key, iv)
    #abcdefghijklmnopqrstuvwxyz0123456789
    plaintext = b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
    buff = ctx.encrypt(plaintext)
    print("Encrypted buffer:")
    print(buff.hex())

    ctx = serpent_cbc(key, iv)
    buff = ctx.decrypt(buff)
    print("Decrypted buffer:")
    print(buff.hex())

    print("--------------------------------")
    print("####### СBC ENCRYPT/DECRYPT #2 #########")
    key = b"\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38"  # if len = 8 we should add 8 zero bytes to the key (SERPENT key sizes: 128,192,256 bit)
    iv = b"\x12"*16
    ctx = serpent_cbc(key, iv)
    print('key = ' + key.hex())
    print('iv = ' + iv.hex())
    # abcdefghijklmnopqrstuvwxyz0123456789
    buff = ctx.encrypt(b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39") #abcdefghijklmnopqrstuvwxyz0123456789
    print("Encrypted buffer:")
    print(buff.hex())

    ctx = serpent_cbc(key, iv)
    buff = ctx.decrypt(buff)
    print("Decrypted buffer:")
    print(buff.hex())
