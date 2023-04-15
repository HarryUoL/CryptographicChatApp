import ast
import socket
import rsa
import json
import random

###test
NonceB1 = 0
NonceS = 0
NonceB = 2
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
privKeyS = rsa.PrivateKey(8368535986424301519677425007078978282009409033444347711859615499370048341703074655505522462102048766899036091098557433327396428069258465008565662942145717, 65537, 6652230812346619649497461482350221288425807910131936744084082717475350382459383323752051550397378681633251414741039522254878998390999853774646427340032513, 7565317343113682473003719157066451814412526235676237417376197496664743312864051731, 1106171176552395053279328787437653065548540673055795968788597324959395607)
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
    input()

    recievingMessage = client.recv(2048).decode(FORMAT)
    #eval(recievingMessage)

    ##this formats SAuthA from string to dict for us
    SAuthB = createSAuthB(recievingMessage)
    #verifys if s responds to nonce
    verified = verifyDS(str(certificate['Nonce1']), SAuthB['DSB'][0], pubKeyS)
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
    eNonceB = encrypt(str(NonceB), pubKeyS)
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

    AAuthA = formatA(recievedMessage1)
    # CAuthA = formatC(recievedMessage2)

    ####GOT TO DO THIS FOR C
    msgtoverifyagainst = str(AAuthA['senderidentity']) + str(AAuthA['recieveridentity']) + str(AAuthA['eNonceA'])
    verifyA = verifyDS(msgtoverifyagainst, AAuthA['DS'], certA['publicKey'])

    if verifyA == 'true':
        # BNonce = decrypt(BAuthA['eNonceB', privKey])
        # stringtodecrypt =
        ANonce = decrypt(AAuthA['eNonceA'], privKey)



    #storeCerts(res1)
    #print("certB=" + str(certB))
    #print("recieved message=" + recievingMessage)
    #print(client.recv(2048).decode(FORMAT))

















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
    #Cert1 = Cert1.replace("PublicKey", "")
    dict_strings = Cert1.split('}')

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'certC' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)

    #d_dict['publicKey'] = rsa.PublicKey(d_dict['publicKey'][0], d_dict['publicKey'][1])
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

    if cert['messagetype'] == "certB":
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
certificate.update({'Nonce1': Nonce1})
msg = formatMsg(str(certificate))
send(msg)



####example of using encrypt,decrypt, digital signature and verify functions
##encrypt
#print("encrypted message-->" + str(encrypt(certificate['Identity'], certificate['Key'])))

#decrypt
#encryptedText = encrypt(certificate['Identity'], certificate['Key'])
#print("decrypted message-->" + str(decrypt(encryptedText, privKey)))

#digital signature
#print("Digital Signature-->" + str(digitalsignature(certificate['Identity']+str(certificate['Key']), privKey)))
#digitalSignature = digitalsignature(certificate['Identity']+str(certificate['Key']), privKey)

##verify digital signature
#it returns true if it verifys it and false if it doesn't
#print(verifyDS(certificate['Identity']+str(certificate['Key']), digitalSignature, pubKeys))

input()

#send(DISCONNECT_MESSAGE)