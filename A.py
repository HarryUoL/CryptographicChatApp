import ast
import msvcrt
import socket
import sys
import time

import rsa
import random
import json
from Crypto.Cipher import AES
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Util.Padding import pad, unpad
import select


#This is As part of Key
#from 0 to largest number in 8 bytes
NonceA = random.randint(0, 2**64-1)

BNonce = 0
CNonce = 0
###test

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
Identity ='A'
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

#public key of S
pubKeyS = rsa.PublicKey(8368535986424301519677425007078978282009409033444347711859615499370048341703074655505522462102048766899036091098557433327396428069258465008565662942145717, 65537)

#certs
certB = {
    "messagetype": "certB",
    "publicKey": None
}
certC = {
    "messagetype": "certC",
    "publicKey": None
}
ArespondS = {
    "messagetype": "ArespondS",
    "eNonceS": None,
    "DSNonceS": None

}
#used for key exchanges to b & C
KeyExchangeB = {
    'messagetype': 'KeyExchangeA',
    'senderidentity': 'A',
    'recieveridentity': 'B',
    'eNonceA': '',
    'DS': ''
}
KeyExchangeC = {
    'messagetype': 'KeyExchangeA',
    'senderidentity': 'A',
    'recieveridentity': 'C',
    'eNonceA': '',
    'DS': ''
}


def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)

    ##sending the cert
    client.send(message)

    print('waiting for others...')
    time.sleep(5)
    print('Enter to start')
    input()
    ####this is the recieved message which we need to verify from S
    recievingMessage = client.recv(2048).decode(FORMAT)


    ##this formats SAuthA from string to dict for us
    SAuthA = createSAuthA(recievingMessage)

    #verifys if s responds to nonce
    verified = verifyDS(str(certificate['Nonce1']), SAuthA['DSA'][0], pubKeyS)
    if verified == 'true':
        ##here we verified our own nonce so we now have to send back nonce of s
        ##encrypted with Ks and the same digitally signed
        NonceS = decrypt(SAuthA['NonceA1&S'][1], privKey)
        eNonceS = encrypt(NonceS, pubKeyS)
        DSNonceS = digitalsignature(NonceS,privKey)

        ArespondS.update({"eNonceS": eNonceS})
        ArespondS.update({"DSNonceS": DSNonceS})
        #conn.send(str(certC).encode(FORMAT))
        msg_length = len(ArespondS)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER - len(send_length))
        client.send(send_length)
        client.send(str(ArespondS).encode(FORMAT))

    ######This is to store certs recieved
    # create 2 dicts out of string
    ##test
    recievingMessageB = client.recv(2048).decode(FORMAT)
    recievingMessageC = client.recv(2048).decode(FORMAT)
    certB = createCertB(recievingMessageB)
    certC = createCertC(recievingMessageC)

##now we send message to s wich is forwared to B/C
## WE NEED TO ADD ENCRYPTED NONCE TO eNonceA
# I NEED TO ADD DIGITAL SIGNATURE OF ALL OF IT TO DS

#KeyExchangeB
    ##how it should be on top
   # eNonceA = encrypt(str(NonceA), certB['publicKey'])
    eNonceA = encrypt(str(NonceA), certB['publicKey'])
    KeyExchangeB.update({'eNonceA': eNonceA})
    #DS
    msgtoDS = str(KeyExchangeB['senderidentity']) + str(KeyExchangeB['recieveridentity']) + str(KeyExchangeB['eNonceA'])
    DSB = digitalsignature(msgtoDS, privKey)
    KeyExchangeB.update({'DS': DSB})

# KeyExchangeC
    #change aswell *******
    #
    #eNonceA = encrypt(NonceA, certC['publicKey'])
    eNonceA = encrypt(str(NonceA), certC['publicKey'])
    KeyExchangeC.update({'eNonceA': eNonceA})
    # DS
    msgtoDS = str(KeyExchangeC['senderidentity']) + str(KeyExchangeC['recieveridentity']) + str(KeyExchangeC['eNonceA'])
    DSC = digitalsignature(msgtoDS, privKey)
    KeyExchangeC.update({'DS': DSC})

####now send them to S
    ## Send the two messages with a delimiter in between
    stringtosend = str(KeyExchangeB) + 'split' + str(KeyExchangeC)
    client.send(stringtosend.encode(FORMAT))

   ###THESE SHOULD THE MESSAGES FROM B AND C
    recievedMessage1 = client.recv(2048).decode(FORMAT)
    #recievedMessage2 = client.recv(2048).decode(FORMAT)
    recievedMessage2 = client.recv(2048).decode(FORMAT)

##### I KNOW NEED TO VERIFY THE RECIEVED MESSAGES AND STORE THE NONCE IN THEM FOR PART OF KEY

##FIRSTLY CHANGE STR TO DICT
#CAuth # out as it is just dummy data atm

    BAuthA = formatB(recievedMessage1)
    CAuthA = formatC(recievedMessage2)

    ####GOT TO DO THIS FOR C
    msgtoverifyagainst = str(BAuthA['senderidentity']) + str(BAuthA['recieveridentity']) + str(BAuthA['eNonceB'])
    verifyB =  verifyDS(msgtoverifyagainst, BAuthA['DS'], certB['publicKey'])

    ##FOR C
    msgtoverifyagainst2 = str(CAuthA['senderidentity']) + str(CAuthA['recieveridentity']) + str(CAuthA['eNonceC'])
    verifyC = verifyDS(msgtoverifyagainst2, CAuthA['DS'], certC['publicKey'])

    if verifyB == 'true':
        #BNonce = decrypt(BAuthA['eNonceB', privKey])
        #stringtodecrypt =
        BNonce = decrypt(BAuthA['eNonceB'], privKey)
        print(BNonce)

    if verifyC == 'true':
        #BNonce = decrypt(BAuthA['eNonceB', privKey])
        #stringtodecrypt =
        CNonce = decrypt(CAuthA['eNonceC'], privKey)
        print(CNonce)


    #########HERE WE START WITH AES (GOT TO DO ABOVE FOR C ASWELL)
    BNonce = int(BNonce)
    CNonce = int(CNonce)
    ###CHANGE NONCES TO BYTES
    ANonce = NonceA.to_bytes(8, byteorder='big')
    BNonce = BNonce.to_bytes(8, byteorder='big')
    CNonce = CNonce.to_bytes(8, byteorder='big')


    ###JOIN THEM TO CREATE KEY
    # Combine the nonces using HKDF
    key_material = ANonce + BNonce + CNonce
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=24,  # 24 bytes = 192 bits
        salt=None,
        info=b'',
    )
    key = hkdf.derive(key_material)

    print(key)
    cipher = AES.new(key, AES.MODE_ECB)
    decipher = AES.new(key, AES.MODE_ECB)

    return cipher, decipher





def AESDecrypt(message, decipher):
    # Unpad the data using PKCS#7 padding
    # unpadded_data = unpad(padded_data, block_size)
    dMessage = decipher.decrypt(message)
    dMessage = unpad(dMessage, AES.block_size).decode('utf-8')

    return dMessage

def AESEncrypt(message, cipher):

    message = message.encode('utf-8')
    # Pad the plaintext to the nearest block boundary using PKCS#7 padding
    # padded_Hello = pad(Hello, AES.block_size)
    # Pad the data using PKCS#7 padding
    block_size = 16
    padding = block_size - len(message) % block_size
    padded_data = message + bytes([padding] * padding)

    eMessage = cipher.encrypt(padded_data)
    return eMessage

def createCertB(Message):

    Cert1= Message.split("split")
    Cert1 = Cert1[0]
    # new_string = my_string.replace("example", "")
    Cert1 = Cert1.replace("PublicKey", "")
    dict_strings = Cert1.split('}')

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:


            if 'certB' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)


    d_dict['publicKey'] = rsa.PublicKey(d_dict['publicKey'][0],d_dict['publicKey'][1])

    return d_dict


def createCertC(Message):
    Cert1 = Message.split("split")
    Cert1 = Cert1[0]
    Cert1 = Cert1.replace("PublicKey", "")
    dict_strings = Cert1.split('}')

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'certC' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)

    d_dict['publicKey'] = rsa.PublicKey(d_dict['publicKey'][0], d_dict['publicKey'][1])
    return d_dict


def createSAuthA(Message):

    Cert1= Message.split("split")
    Cert1 = Cert1[0]

    #dict_strings = Cert1.split('}')
    dict_strings = Cert1.rsplit('}', 1)

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'SAuthA' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)

    return d_dict


def formatB(Message):

    Cert1= Message.split("split")
    Cert1 = Cert1[0]

    #dict_strings = Cert1.split('}')
    dict_strings = Cert1.rsplit('}', 1)

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'KeyExchangeB' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)

    return d_dict

def formatC(Message):

    Cert1= Message.split("split")
    Cert1 = Cert1[0]

    #dict_strings = Cert1.split('}')
    dict_strings = Cert1.rsplit('}', 1)

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'KeyExchangeC' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)

    return d_dict

def formatCerts(Message):
    Message = Message.replace("[", "")
    Message = Message.replace("]", "")
    Message = Message.replace("'"'', "")

    return Message


def encrypt(msgencrypt, key):
    message = msgencrypt.encode(FORMAT)
    msgencrypt = rsa.encrypt(message, key)
    return msgencrypt


def decrypt(msgdecrypt, key):
    msgdecrypt = rsa.decrypt(msgdecrypt, key)
    msgdecrypt = msgdecrypt.decode(FORMAT)
    return msgdecrypt


def digitalsignature(msgSign, key):
    msgSign = msgSign.encode(FORMAT)
    msgSign = rsa.sign(msgSign, key, 'SHA-256')
    return msgSign


def verifyDS(msgVerify, signature, key):
    msgVerify = msgVerify.encode(FORMAT)
    msgVerify = rsa.verify(msgVerify, signature, key)
    if msgVerify == 'SHA-256':
        true = 'true'
        return true
    else:
        false ='false'
        return false

##keys

(pubKeys, privKey) = rsa.newkeys(512)

def storeCerts(cert):

    if cert['messagetype'] == "certB":
        certB.update({'publicKey': cert['Key']})

    elif cert['messagetype'] == "certC":
        certC.update({'publicKey': cert['Key']})

def formatMsg(msg):
    msg = msg.replace("PublicKey", "")
    return msg


####with dict
#digitalsignature(certificate['Identity']+str(certificate['Key']), privKey)

##this is the hash of our identity and publickey digitally signed with our private
DS = digitalsignature(Identity+str(pubKeys), privKey)


certificate = {
    "Key": pubKeys,
    "Identity": "A",
    "messagetype": "certA",
    "Nonce1": 0,
    "DigitalSignature": DS

}
####
Nonce1 = random.randint(0, 2**64-1)

certificate.update({'Nonce1': Nonce1})

msg = formatMsg(str(certificate))
cipher, decipher = send(msg)






connected = True
messagesDict = {}
while connected:

    message = input('Enter message to send: ')
    if message:
        message = AESEncrypt(message, cipher)
        client.send(message)


    message = input('Press enter to update messages ')

    # receive any incoming messages from the server

    message = client.recv(2048)

    if message:
        #message = message.encode(FORMAT)
        messages = eval(message)

        # Iterate over the values of the dictionary and decrypt each one
        for key in messages:
            messagesToStore = AESDecrypt(messages[key], decipher)
            #encrypted_dict[key] = encrypted_value
            messagesDict[key] = messagesToStore

        #message = AESDecrypt(message, decipher)
        print('Received message:', messagesDict)

    else:
       print('Received message:', messagesDict)




input()
#send(DISCONNECT_MESSAGE)