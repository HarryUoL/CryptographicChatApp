import ast
import select
import socket
import rsa
import json
import random
from Crypto.Cipher import AES
import Crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Util.Padding import pad, unpad
import time

###test
NonceB1 = 0
NonceS = 0
NonceB = random.randint(0, 2**64-1)
ANonce = 0
CNonce = 0
###test

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
Identity ='B'
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

pubKeyS = rsa.PublicKey(8368535986424301519677425007078978282009409033444347711859615499370048341703074655505522462102048766899036091098557433327396428069258465008565662942145717, 65537)

certA = {
    "messagetype": "certA",
    "publicKey": None
}
certC = {
    "messagetype": "certC",
    "publicKey": None
}
BrespondS = {
    "messagetype": "BrespondS",
    "eNonceS": None,
    "DSNonceS": None

}
KeyExchangeA = {
    'messagetype': 'KeyExchangeB',
    'senderidentity': 'B',
    'recieveridentity': 'A',
    'eNonceB': '',
    'DS': ''
}
KeyExchangeC = {
    'messagetype': 'KeyExchangeB',
    'senderidentity': 'B',
    'recieveridentity': 'C',
    'eNonceB': '',
    'DS': ''
}


def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    ####this is the recieved message
    #input()
    print('waiting for others...')
    time.sleep(5)
    print('Enter to start')
    input()

    recievingMessage = client.recv(2048).decode(FORMAT)
    #eval(recievingMessage)

    ##this formats SAuthA from string to dict for us
    SAuthB = createSAuthB(recievingMessage)
    #verifys if s responds to nonce
    verified = verifyDS(nonce1, SAuthB['DSB'][0], pubKeyS)
    if verified == 'true':
        ##here we verified our own nonce so we now have to send back nonce of s
        ##encrypted with Ks and the same digitally signed
        NonceS = decrypt(SAuthB['NonceB1&S'][1], privKey)
        eNonceS = encrypt(NonceS, pubKeyS)
        DSNonceS = digitalsignature(NonceS, privKey)

        BrespondS.update({"eNonceS": eNonceS})
        BrespondS.update({"DSNonceS": DSNonceS})
        #conn.send(str(certC).encode(FORMAT))
        msg_length = len(BrespondS)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER - len(send_length))
        client.send(send_length)
        client.send(str(BrespondS).encode(FORMAT))

    ######This is to store certs recieved
    # create 2 dicts out of string
    ##test
    recievingMessageA = client.recv(2048).decode(FORMAT)
    recievingMessageC = client.recv(2048).decode(FORMAT)
    certA = createCertA(recievingMessageA)
    certC = createCertC(recievingMessageC)

##now we send message to s wich is forwared to B/C
## WE NEED TO ADD ENCRYPTED NONCE TO eNonceA
# I NEED TO ADD DIGITAL SIGNATURE OF ALL OF IT TO DS

#KeyExchangeA
    ##how it should be on top
   # eNonceA = encrypt(str(NonceA), certB['publicKey'])
    eNonceB = encrypt(str(NonceB), certA['publicKey'])
    #eNonceB = encrypt(str(NonceB), pubKeyS)
    KeyExchangeA.update({'eNonceB': eNonceB})
    #DS
    msgtoDS = str(KeyExchangeA['senderidentity']) + str(KeyExchangeA['recieveridentity']) + str(KeyExchangeA['eNonceB'])
    DSA = digitalsignature(msgtoDS, privKey)
    KeyExchangeA.update({'DS': DSA})

# KeyExchangeC
    #change aswell *******
    #eNonceA = encrypt(NonceA, certC['publicKey'])
    eNonceB = encrypt(str(NonceB), certC['publicKey'])
    KeyExchangeC.update({'eNonceB': eNonceB})
    # DS
    msgtoDS = str(KeyExchangeC['senderidentity']) + str(KeyExchangeC['recieveridentity']) + str(KeyExchangeC['eNonceB'])
    DSC = digitalsignature(msgtoDS, privKey)
    KeyExchangeC.update({'DS': DSC})

####now send them to S
    ## Send the two messages with a delimiter in between
    stringtosend = str(KeyExchangeA) + 'split' + str(KeyExchangeC)
    client.send(stringtosend.encode(FORMAT))

    ###THESE SHOULD THE MESSAGES FROM B AND C
    recievedMessage1 = client.recv(2048).decode(FORMAT)
    recievedMessage2 = client.recv(2048).decode(FORMAT)

    ##### I KNOW NEED TO VERIFY THE RECIEVED MESSAGES AND STORE THE NONCE IN THEM FOR PART OF KEY

    ##FIRSTLY CHANGE STR TO DICT
    # CAuth # out as it is just dummy data atm

    AAuthB = formatA(recievedMessage1)
    CAuthB = formatC(recievedMessage2)

    ####GOT TO DO THIS FOR C
    msgtoverifyagainst = str(AAuthB['senderidentity']) + str(AAuthB['recieveridentity']) + str(AAuthB['eNonceA'])
    verifyA = verifyDS(msgtoverifyagainst, AAuthB['DS'], certA['publicKey'])

    #FOR C
    msgtoverifyagainst = str(CAuthB['senderidentity']) + str(CAuthB['recieveridentity']) + str(CAuthB['eNonceC'])
    verifyC = verifyDS(msgtoverifyagainst, CAuthB['DS'], certC['publicKey'])


    if verifyA == 'true':
        # BNonce = decrypt(BAuthA['eNonceB', privKey])
        # stringtodecrypt =
        ANonce = decrypt(AAuthB['eNonceA'], privKey)

    if verifyC == 'true':
        # BNonce = decrypt(BAuthA['eNonceB', privKey])
        # stringtodecrypt =
        CNonce = decrypt(CAuthB['eNonceC'], privKey)

    #########HERE WE START WITH AES (GOT TO DO ABOVE FOR C ASWELL)
    ANonce = int(ANonce)
    CNonce = int(CNonce)
    ###CHANGE NONCES TO BYTES
    ANonce = ANonce.to_bytes(8, byteorder='big')
    BNonce = NonceB.to_bytes(8, byteorder='big')
    CNonce = CNonce.to_bytes(8, byteorder='big')


    ###JOIN THEM TO CREATE KEY
    # Combine the nonces using HKDF
    key_material = ANonce + BNonce + CNonce
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=24,  # 32 bytes = 256 bits
        salt=None,
        info=b'',
)
    key = hkdf.derive(key_material)


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















def createCertA(Message):

    Cert1= Message.split("split")
    Cert1 = Cert1[0]
    Cert1 = Cert1.replace("PublicKey", "")
    dict_strings = Cert1.split('}')

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'certA' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)

    #print(d_dict)
  #  print(d_dict2)

    d_dict['publicKey'] = rsa.PublicKey(d_dict['publicKey'][0], d_dict['publicKey'][1])
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


def createSAuthB(Message):

    Cert1= Message.split("split")
    Cert1 = Cert1[0]
    #Cert1 = Cert1.replace("PublicKey", "")

    dict_strings = Cert1.rsplit('}', 1)

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'SAuthB' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)




    return d_dict


def formatA(Message):

    Cert1= Message.split("split")
    Cert1 = Cert1[0]

    #dict_strings = Cert1.split('}')
    dict_strings = Cert1.rsplit('}', 1)

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'KeyExchangeA' in d_str:
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

    if cert['messagetype'] == "certA":
        certA.update({'publicKey': cert['Key']})

    elif cert['messagetype'] == "certC":
        certC.update({'publicKey': cert['Key']})

def formatMsg(msg):
    msg = msg.replace("PublicKey", "")
    return msg


####with dict
#digitalsignature(certificate['Identity']+str(certificate['Key']), privKey)
DS = digitalsignature(Identity+str(pubKeys), privKey)

certificate = {
    "Key": pubKeys,
    "Identity": "B",
    "messagetype": "certB",
    "Nonce1": 0,
    "DigitalSignature": DS

}
####
Nonce1 = random.randint(0, 2**64-1)
Nonce1 = str(Nonce1)
nonce1 = Nonce1
Nonce1 = encrypt(Nonce1, pubKeyS)
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