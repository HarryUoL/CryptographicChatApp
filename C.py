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

###test
NonceB1 = 0
NonceS = 0
NonceC = random.randint(0, 2**64-1)
ANonce = 0
BNonce = 0
###test

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
Identity ='C'
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

pubKeyS = rsa.PublicKey(8368535986424301519677425007078978282009409033444347711859615499370048341703074655505522462102048766899036091098557433327396428069258465008565662942145717, 65537)
privKeyS = rsa.PrivateKey(8368535986424301519677425007078978282009409033444347711859615499370048341703074655505522462102048766899036091098557433327396428069258465008565662942145717, 65537, 6652230812346619649497461482350221288425807910131936744084082717475350382459383323752051550397378681633251414741039522254878998390999853774646427340032513, 7565317343113682473003719157066451814412526235676237417376197496664743312864051731, 1106171176552395053279328787437653065548540673055795968788597324959395607)
certA = {
    "messagetype": "certA",
    "publicKey": None
}
certB = {
    "messagetype": "certC",
    "publicKey": None
}
CrespondS = {
    "messagetype": "CrespondS",
    "eNonceS": None,
    "DSNonceS": None

}
KeyExchangeA = {
    'messagetype': 'KeyExchangeC',
    'senderidentity': 'C',
    'recieveridentity': 'A',
    'eNonceC': '',
    'DS': ''
}
KeyExchangeB = {
    'messagetype': 'KeyExchangeC',
    'senderidentity': 'C',
    'recieveridentity': 'B',
    'eNonceC': '',
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
    input()

    recievingMessage = client.recv(2048).decode(FORMAT)
    #eval(recievingMessage)

    ##this formats SAuthA from string to dict for us
    SAuthC = createSAuthC(recievingMessage)
    #verifys if s responds to nonce
    verified = verifyDS(str(certificate['Nonce1']), SAuthC['DSC'][0], pubKeyS)
    if verified == 'true':
        ##here we verified our own nonce so we now have to send back nonce of s
        ##encrypted with Ks and the same digitally signed
        NonceS = decrypt(SAuthC['NonceC1&S'][1], privKey)
        eNonceS = encrypt(NonceS, pubKeyS)
        DSNonceS = digitalsignature(NonceS, privKey)

        CrespondS.update({"eNonceS": eNonceS})
        CrespondS.update({"DSNonceS": DSNonceS})
        #conn.send(str(certC).encode(FORMAT))
        msg_length = len(CrespondS)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER - len(send_length))
        client.send(send_length)
        client.send(str(CrespondS).encode(FORMAT))

    ######This is to store certs recieved
    # create 2 dicts out of string
    ##test
    recievingMessageA = client.recv(2048).decode(FORMAT)
    recievingMessageB = client.recv(2048).decode(FORMAT)
    certA = createCertA(recievingMessageA)
    certB = createCertB(recievingMessageB)

##now we send message to s wich is forwared to B/C
## WE NEED TO ADD ENCRYPTED NONCE TO eNonceA
# I NEED TO ADD DIGITAL SIGNATURE OF ALL OF IT TO DS

#KeyExchangeA
    ##how it should be on top
   # eNonceA = encrypt(str(NonceA), certB['publicKey'])
    eNonceC = encrypt(str(NonceC), certA['publicKey'])
    #eNonceB = encrypt(str(NonceB), pubKeyS)
    KeyExchangeA.update({'eNonceC': eNonceC})
    #DS
    msgtoDS = str(KeyExchangeA['senderidentity']) + str(KeyExchangeA['recieveridentity']) + str(KeyExchangeA['eNonceC'])
    DSA = digitalsignature(msgtoDS, privKey)
    KeyExchangeA.update({'DS': DSA})

# KeyExchangeB
    #change aswell *******
    #eNonceA = encrypt(NonceA, certC['publicKey'])
    eNonceC = encrypt(str(NonceC), certB['publicKey'])
    KeyExchangeB.update({'eNonceC': eNonceC})
    # DS
    msgtoDS = str(KeyExchangeB['senderidentity']) + str(KeyExchangeB['recieveridentity']) + str(KeyExchangeB['eNonceC'])
    DSB = digitalsignature(msgtoDS, privKey)
    KeyExchangeB.update({'DS': DSB})

####now send them to S
    ## Send the two messages with a delimiter in between
    stringtosend = str(KeyExchangeA) + 'split' + str(KeyExchangeB)
    client.send(stringtosend.encode(FORMAT))

    ###THESE SHOULD THE MESSAGES FROM A AND B
    recievedMessage1 = client.recv(2048).decode(FORMAT)
    recievedMessage2 = client.recv(2048).decode(FORMAT)

    ##### I KNOW NEED TO VERIFY THE RECIEVED MESSAGES AND STORE THE NONCE IN THEM FOR PART OF KEY

    ##FIRSTLY CHANGE STR TO DICT
    # CAuth # out as it is just dummy data atm

    AAuthC = formatA(recievedMessage1)
    BAuthC = formatB(recievedMessage2)

    ####GOT TO DO THIS FOR C
    msgtoverifyagainst = str(AAuthC['senderidentity']) + str(AAuthC['recieveridentity']) + str(AAuthC['eNonceA'])
    verifyA = verifyDS(msgtoverifyagainst, AAuthC['DS'], certA['publicKey'])

    #FOR C
    msgtoverifyagainst = str(BAuthC['senderidentity']) + str(BAuthC['recieveridentity']) + str(BAuthC['eNonceB'])
    verifyB = verifyDS(msgtoverifyagainst, BAuthC['DS'], certB['publicKey'])


    if verifyA == 'true':
        # BNonce = decrypt(BAuthA['eNonceB', privKey])
        # stringtodecrypt =
        ANonce = decrypt(AAuthC['eNonceA'], privKey)

    if verifyB == 'true':
        # BNonce = decrypt(BAuthA['eNonceB', privKey])
        # stringtodecrypt =
        BNonce = decrypt(BAuthC['eNonceB'], privKey)

    #########HERE WE START WITH AES (GOT TO DO ABOVE FOR C ASWELL)

###CHANGE NONCES TO BYTES
ANonce = ANonce.to_bytes(8, byteorder='big')
BNonce = BNonce.to_bytes(8, byteorder='big')
CNonce = NonceC.to_bytes(8, byteorder='big')


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


def createCertB(Message):
    Cert1 = Message.split("split")
    Cert1 = Cert1[0]
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

    d_dict['publicKey'] = rsa.PublicKey(d_dict['publicKey'][0], d_dict['publicKey'][1])
    return d_dict


def createSAuthC(Message):

    Cert1= Message.split("split")
    Cert1 = Cert1[0]
    #Cert1 = Cert1.replace("PublicKey", "")

    dict_strings = Cert1.rsplit('}', 1)

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'SAuthC' in d_str:
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

    elif cert['messagetype'] == "certA":
        certA.update({'publicKey': cert['Key']})

def formatMsg(msg):
    msg = msg.replace("PublicKey", "")
    return msg


####with dict
#digitalsignature(certificate['Identity']+str(certificate['Key']), privKey)
DS = digitalsignature(Identity+str(pubKeys), privKey)

certificate = {
    "Key": pubKeys,
    "Identity": "C",
    "messagetype": "certC",
    "Nonce1": 0,
    "DigitalSignature": DS

}
####
Nonce1 = random.randint(0, 2**64-1)
certificate.update({'Nonce1': Nonce1})
msg = formatMsg(str(certificate))
send(msg)




connected = True
while connected:
    read_sockets, _, exception_sockets = select.select([client], [client], [client])

    # handle any exceptions that may have occurred
    for sock in exception_sockets:
        print('Error occurred with socket:', sock)

    # receive any incoming messages from the server
    for sock in read_sockets:
        message = sock.recv(2048).decode(FORMAT)
        if not message:
            print('Server has disconnected.')
            #exit()
        print('Received message:', message)

    # allow the user to input a message to send to the server
    message = input('Enter message to send: ')
    if message:
        client.send(message.encode(FORMAT))


input()