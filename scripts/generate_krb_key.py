#!/usr/bin/env python3

from binascii import unhexlify, hexlify

from impacket.krb5 import constants
from impacket.krb5.crypto import Key, string_to_key
from Cryptodome.Hash import MD4

allciphers = {
    'rc4_hmac_nt': int(constants.EncryptionTypes.rc4_hmac.value),
    'aes128_hmac': int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
    'aes256_hmac': int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)
}

def printKerberosKeys(password, salt):
    for name, cipher in allciphers.items():
        if cipher == 23:
            md4 = MD4.new()
            md4.update(password)
            key = Key(cipher, md4.digest())
        else:
            fixedPassword = password.decode('utf-16-le', 'replace').encode('utf-8', 'replace')
            key = string_to_key(cipher, fixedPassword, salt)

        print(f'    * {name}: {hexlify(key.contents).decode("utf-8")}')

def printMachineKerberosKeys(domain, hostname, hexpassword):
    salt = b'%shost%s.%s' % (domain.upper().encode('utf-8'), hostname.lower().encode('utf-8'), domain.lower().encode('utf-8'))
    rawpassword = unhexlify(hexpassword)
    print(f'{domain.upper()}\\{hostname.upper()}$')
    print(f'    * Salt: {salt.decode("utf-8")}')
    printKerberosKeys(rawpassword, salt)

def printUserKerberosKeys(domain, username, rawpassword):
    salt = b'%s%s' % (domain.upper().encode('utf-8'), username.encode('utf-8'))
    rawpassword = rawpassword.encode('utf-16-le')
    print(f'{domain.upper()}\\{username}')
    print(f'    * Salt: {salt.decode("utf-8")}')
    printKerberosKeys(rawpassword, salt)


printUserKerberosKeys(
    domain='hpbank.local',
    username='da',
    rawpassword='P@ssw0rd'
)

printMachineKerberosKeys(
    domain='hpbank.local',
    hostname='web',
    hexpassword='710056006c0053003700340069006b00320049006b002a007a005700610028002d00380071004c00730024002c0066006b0031004000310035005200630062003700430057002600390046003400680065002d00260026004a0063006000210060004b00250028007a0057005a00420051002a006c003100300027004100280030006f00320037004a0048003d0040006c004200520078003e0044003600290056007700460054006d00470033004a003f006c0055002900560074003100200049003c004f006a004e00280068003c0038005400650035004c005300670040002b005c00290063003b004c004c002f00'
)