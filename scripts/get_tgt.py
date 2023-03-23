#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Given a password, hash or aesKey, it will request a TGT and save it as ccache
#
#   Examples:
#       ./getTGT.py -hashes lm:nt contoso.com/user
#
# Author:
#   Alberto Solino (@agsolino)
#

from __future__ import division
from __future__ import print_function
import argparse
import logging
import sys
import datetime
import random
import socket
import struct
from binascii import unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import noValue, Sequence
from pyasn1.type.useful import GeneralizedTime
from six import b
from binascii import unhexlify, hexlify

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
#from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal

from impacket.krb5.asn1 import AS_REQ, AP_REQ, TGS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, PA_ENC_TS_ENC, AS_REP, TGS_REP, \
    EncryptedData, Authenticator, EncASRepPart, EncTGSRepPart, seq_set, seq_set_iter, KERB_ERROR_DATA, METHOD_DATA, \
    ETYPE_INFO2, ETYPE_INFO, AP_REP, EncAPRepPart
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.krb5.gssapi import CheckSumField, GSS_C_DCE_STYLE, GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, \
    GSS_C_SEQUENCE_FLAG, GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG
from impacket.krb5 import constants
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum
from impacket.smbconnection import SessionError
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp, ASN1_OID, asn1encode, ASN1_AID
from impacket.krb5.gssapi import KRB5_AP_REQ
from impacket import nt_errors, LOG
from impacket.krb5.ccache import CCache

# Our random number generator
try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass

def sendReceive(data, host, kdcHost):
    if kdcHost is None:
        targetHost = host
    else:
        targetHost = kdcHost

    messageLen = struct.pack('!i', len(data))

    LOG.debug('Trying to connect to KDC at %s' % targetHost)
    try:
        af, socktype, proto, canonname, sa = socket.getaddrinfo(targetHost, 88, 0, socket.SOCK_STREAM)[0]
        s = socket.socket(af, socktype, proto)
        s.connect(sa)
    except socket.error as e:
        raise socket.error("Connection error (%s:%s)" % (targetHost, 88), e)

    s.sendall(messageLen + data)

    recvDataLen = struct.unpack('!i', s.recv(4))[0]

    r = s.recv(recvDataLen)
    while len(r) < recvDataLen:
        r += s.recv(recvDataLen-len(r))

    try:
        krbError = KerberosError(packet = decoder.decode(r, asn1Spec = KRB_ERROR())[0])
    except:
        return r

    if krbError.getErrorCode() != constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
        try:
            for i in decoder.decode(r):
                if type(i) == Sequence:
                    for k in vars(i)["_componentValues"]:
                        if type(k) == GeneralizedTime:
                            server_time = datetime.datetime.strptime(k.asOctets().decode("utf-8"), "%Y%m%d%H%M%SZ")
                            LOG.debug("Server time (UTC): %s" % server_time)
        except:
            # Couldn't get server time for some reason
            pass
        raise krbError

    return r

def getKerberosTGT(clientName, password, domain, lmhash, nthash, aesKey='', kdcHost=None, requestPAC=True):

    # Convert to binary form, just in case we're receiving strings
    if isinstance(lmhash, str):
        try:
            lmhash = unhexlify(lmhash)
        except TypeError:
            pass
    if isinstance(nthash, str):
        try:
            nthash = unhexlify(nthash)
        except TypeError:
            pass
    if isinstance(aesKey, str):
        try:
            aesKey = unhexlify(aesKey)
        except TypeError:
            pass

    asReq = AS_REQ()

    domain = domain.upper()
    serverName = Principal('krbtgt/%s'%domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)  

    pacRequest = KERB_PA_PAC_REQUEST()
    pacRequest['include-pac'] = requestPAC
    encodedPacRequest = encoder.encode(pacRequest)

    asReq['pvno'] = 5
    asReq['msg-type'] =  int(constants.ApplicationTagNumbers.AS_REQ.value)

    asReq['padata'] = noValue
    asReq['padata'][0] = noValue
    asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    asReq['padata'][0]['padata-value'] = encodedPacRequest

    reqBody = seq_set(asReq, 'req-body')

    opts = list()
    opts.append( constants.KDCOptions.forwardable.value )
    opts.append( constants.KDCOptions.renewable.value )
    opts.append( constants.KDCOptions.proxiable.value )
    reqBody['kdc-options']  = constants.encodeFlags(opts)

    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    seq_set(reqBody, 'cname', clientName.components_to_asn1)

    if domain == '':
        raise Exception('Empty Domain not allowed in Kerberos')

    reqBody['realm'] = domain

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    reqBody['till'] = KerberosTime.to_asn1(now)
    reqBody['rtime'] = KerberosTime.to_asn1(now)
    reqBody['nonce'] =  rand.getrandbits(31)

    # Yes.. this shouldn't happen but it's inherited from the past
    if aesKey is None:
        aesKey = b''

    if nthash == b'':
        # This is still confusing. I thought KDC_ERR_ETYPE_NOSUPP was enough, 
        # but I found some systems that accepts all ciphers, and trigger an error 
        # when requesting subsequent TGS :(. More research needed.
        # So, in order to support more than one cypher, I'm setting aes first
        # since most of the systems would accept it. If we're lucky and 
        # KDC_ERR_ETYPE_NOSUPP is returned, we will later try rc4.
        if aesKey != b'':
            if len(aesKey) == 32:
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),)
            else:
                supportedCiphers = (int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
        else:
            supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),)
    else:
        # We have hashes to try, only way is to request RC4 only
        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

    seq_set_iter(reqBody, 'etype', supportedCiphers)

    message = encoder.encode(asReq)

    try:
        r = sendReceive(message, domain, kdcHost)
    except KerberosError as e:
        if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
            if supportedCiphers[0] in (constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value) and aesKey == b'':
                supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, kdcHost)
            else: 
                raise 
        else:
            raise 

    # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
    # 'Do not require Kerberos preauthentication' set
    preAuth = True
    try:
        asRep = decoder.decode(r, asn1Spec = KRB_ERROR())[0]
    except:
        # Most of the times we shouldn't be here, is this a TGT?
        asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        # Yes
        preAuth = False
    
    #print (asRep)

    encryptionTypesData = dict()
    salt = ''
    if preAuth is False:
        # In theory, we should have the right credentials for the etype specified before.
        methods = asRep['padata']
        print (methods)
        encryptionTypesData[supportedCiphers[0]] = salt # handle RC4 fallback, we don't need any salt
        tgt = r
    else:
        methods = decoder.decode(asRep['e-data'], asn1Spec=METHOD_DATA())[0]
        print (methods)

    for method in methods:
        if method['padata-type'] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
            etypes2 = decoder.decode(method['padata-value'], asn1Spec = ETYPE_INFO2())[0]
            for etype2 in etypes2:
                try:
                    if etype2['salt'] is None or etype2['salt'].hasValue() is False:
                        salt = ''
                    else:
                        salt = etype2['salt'].prettyPrint()
                except PyAsn1Error:
                    salt = ''

                encryptionTypesData[etype2['etype']] = b(salt)
        elif method['padata-type'] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO.value:
            etypes = decoder.decode(method['padata-value'], asn1Spec = ETYPE_INFO())[0]
            for etype in etypes:
                try:
                    if etype['salt'] is None or etype['salt'].hasValue() is False:
                        salt = ''
                    else:
                        salt = etype['salt'].prettyPrint()
                except PyAsn1Error:
                    salt = ''

                encryptionTypesData[etype['etype']] = b(salt)

    

    enctype = supportedCiphers[0]

    cipher = _enctype_table[enctype]

    # Pass the hash/aes key :P
    if isinstance(nthash, bytes) and nthash != b'':
        key = Key(cipher.enctype, nthash)
    elif aesKey != b'':
        key = Key(cipher.enctype, aesKey)
    else:
        key = cipher.string_to_key(password, encryptionTypesData[enctype], None)

    if preAuth is True:
        if enctype in encryptionTypesData is False:
            raise Exception('No Encryption Data Available!')

        # Let's build the timestamp
        timeStamp = PA_ENC_TS_ENC()

        now = datetime.datetime.utcnow()
        timeStamp['patimestamp'] = KerberosTime.to_asn1(now)
        timeStamp['pausec'] = now.microsecond

        # Encrypt the shyte
        encodedTimeStamp = encoder.encode(timeStamp)

        # Key Usage 1
        # AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the
        # client key (Section 5.2.7.2)
        encriptedTimeStamp = cipher.encrypt(key, 1, encodedTimeStamp, None)

        encryptedData = EncryptedData()
        encryptedData['etype'] = cipher.enctype
        encryptedData['cipher'] = encriptedTimeStamp
        encodedEncryptedData = encoder.encode(encryptedData)

        # Now prepare the new AS_REQ again with the PADATA
        # ToDo: cannot we reuse the previous one?
        asReq = AS_REQ()

        asReq['pvno'] = 5
        asReq['msg-type'] =  int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
        asReq['padata'][0]['padata-value'] = encodedEncryptedData

        asReq['padata'][1] = noValue
        asReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][1]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append( constants.KDCOptions.forwardable.value )
        opts.append( constants.KDCOptions.renewable.value )
        opts.append( constants.KDCOptions.proxiable.value )
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        reqBody['realm'] =  domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] =  KerberosTime.to_asn1(now)
        reqBody['nonce'] = rand.getrandbits(31)

        seq_set_iter(reqBody, 'etype', ( (int(cipher.enctype),)))

        try:
            tgt = sendReceive(encoder.encode(asReq), domain, kdcHost)
        except Exception as e:
            if str(e).find('KDC_ERR_ETYPE_NOSUPP') >= 0:
                if lmhash == b'' and nthash == b'' and (aesKey == b'' or aesKey is None):
                    from impacket.ntlm import compute_lmhash, compute_nthash
                    lmhash = compute_lmhash(password)
                    nthash = compute_nthash(password)
                    return getKerberosTGT(clientName, password, domain, lmhash, nthash, aesKey, kdcHost, requestPAC)
            raise


        asRep = decoder.decode(tgt, asn1Spec = AS_REP())[0]
        print (asRep)

    # So, we have the TGT, now extract the new session key and finish
    cipherText = asRep['enc-part']['cipher']

    if preAuth is False:
        # Let's output the TGT enc-part/cipher in John format, in case somebody wants to use it.
        LOG.debug('$krb5asrep$%d$%s@%s:%s$%s' % (asRep['enc-part']['etype'],clientName, domain, hexlify(asRep['enc-part']['cipher'].asOctets()[:16]),
                                           hexlify(asRep['enc-part']['cipher'].asOctets()[16:])) )
    # Key Usage 3
    # AS-REP encrypted part (includes TGS session key or
    # application session key), encrypted with the client key
    # (Section 5.4.2)
    try:
        plainText = cipher.decrypt(key, 3, cipherText)
        
    except InvalidChecksum as e:
        # probably bad password if preauth is disabled
        if preAuth is False:
            error_msg = "failed to decrypt session key: %s" % str(e)
            raise SessionKeyDecryptionError(error_msg, asRep, cipher, key, cipherText)
        raise
    encASRepPart = decoder.decode(plainText, asn1Spec = EncASRepPart())[0]
    print (encASRepPart)

    # Get the session key and the ticket
    cipher = _enctype_table[encASRepPart['key']['keytype']]
    sessionKey = Key(cipher.enctype,encASRepPart['key']['keyvalue'].asOctets())

    # ToDo: Check Nonces!

    return tgt, cipher, key, sessionKey

class KerberosError(SessionError):
    """
    This is the exception every client should catch regardless of the underlying
    SMB version used. We'll take care of that. NETBIOS exceptions are NOT included,
    since all SMB versions share the same NETBIOS instances.
    """
    def __init__( self, error = 0, packet=0):
        SessionError.__init__(self)
        self.error = error
        self.packet = packet
        if packet != 0:
            self.error = self.packet['error-code']
       
    def getErrorCode( self ):
        return self.error

    def getErrorPacket( self ):
        return self.packet

    def getErrorString( self ):
        return constants.ERROR_MESSAGES[self.error]

    def __str__( self ):
        retString = 'Kerberos SessionError: %s(%s)' % (constants.ERROR_MESSAGES[self.error])
        try:
            # Let's try to get the NT ERROR, if not, we quit and give the general one
            if self.error == constants.ErrorCodes.KRB_ERR_GENERIC.value:
                eData = decoder.decode(self.packet['e-data'], asn1Spec = KERB_ERROR_DATA())[0]
                nt_error = struct.unpack('<L', eData['data-value'].asOctets()[:4])[0]
                retString += '\nNT ERROR: %s(%s)' % (nt_errors.ERROR_MESSAGES[nt_error])
        except:
            pass

        return retString

class GETTGT:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__user= target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__options = options
        self.__kdcHost = options.dc_ip
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def saveTicket(self, ticket, sessionKey):
        logging.info('Saving ticket in %s' % (self.__user + '.ccache'))
        from impacket.krb5.ccache import CCache
        ccache = CCache()

        ccache.fromTGT(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__user + '.ccache')

    def run(self):
        userName = Principal(self.__user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash), unhexlify(self.__nthash), self.__aesKey,
                                                                self.__kdcHost)
        #self.saveTicket(tgt,oldSessionKey)
        #print (tgt)


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Given a password, hash or aesKey, it will request a "
                                                                "TGT and save it as ccache")
    parser.add_argument('identity', action='store', help='[domain/]username[:password]')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv)==1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./getTGT.py -hashes lm:nt contoso.com/user\n")
        print("\tit will use the lm:nt hashes for authentication. If you don't specify them, a password will be asked")
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.identity)

    try:
        if domain is None:
            logging.critical('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        executer = GETTGT(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))