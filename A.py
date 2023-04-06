import ast
import socket
import rsa
import json

###test
NonceA1 = 3
NonceS = 0
NonceA = 2
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

pubKeyS = rsa.PublicKey(8368535986424301519677425007078978282009409033444347711859615499370048341703074655505522462102048766899036091098557433327396428069258465008565662942145717, 65537)

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
    client.send(message)
    ####this is the recieved message
    input()

    recievingMessage = client.recv(2048).decode(FORMAT)
    #eval(recievingMessage)

    ##this formats SAuthA from string to dict for us
    SAuthA = createSAuthA(recievingMessage)
    #verifys if s responds to nonce
    verified = verifyDS(str(NonceA1), SAuthA['DSA'][0], pubKeyS)
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
    eNonceA = encrypt(str(NonceA), pubKeyS)
    KeyExchangeB.update({'eNonceA': eNonceA})
    #DS
    msgtoDS = str(KeyExchangeB['senderidentity']) + str(KeyExchangeB['recieveridentity']) + str(KeyExchangeB['eNonceA'])
    DSB = digitalsignature(msgtoDS, privKey)
    KeyExchangeB.update({'DS': DSB})

# KeyExchangeC
    #change aswell *******
    #eNonceA = encrypt(NonceA, certC['publicKey'])
    eNonceA = encrypt(str(NonceA), pubKeyS)
    KeyExchangeC.update({'eNonceA': eNonceA})
    # DS
    msgtoDS = str(KeyExchangeC['senderidentity']) + str(KeyExchangeC['recieveridentity']) + str(KeyExchangeC['eNonceA'])
    DSC = digitalsignature(msgtoDS, privKey)
    KeyExchangeC.update({'DS': DSC})

####now send them to S
    ## Send the two messages with a delimiter in between
    stringtosend = str(KeyExchangeB) + '|' + str(KeyExchangeC)
    client.send(stringtosend.encode(FORMAT))
    print('hi')


   # client.send(str(KeyExchangeB).encode(FORMAT))
   # client.send(str(KeyExchangeC).encode(FORMAT))





    #storeCerts(res1)
    #print("certB=" + str(certB))
    print("recieved message=" + recievingMessage)
    #print(client.recv(2048).decode(FORMAT))


def createCertB(Message):

    Cert1= Message.split("split")
    Cert1 = Cert1[0]

    dict_strings = Cert1.split('}')

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'certB' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)

    #print(d_dict)
  #  print(d_dict2)


    return d_dict


def createCertC(Message):
    Cert1 = Message.split("split")
    Cert1 = Cert1[0]

    dict_strings = Cert1.split('}')

    # iterate over the dictionary strings and extract the dictionary key-value pairs
    for d_str in dict_strings:
        if d_str:
            if 'certC' in d_str:
                # add back the '}' character removed by the split method
                d_str += '}'
                # convert the dictionary string to a dictionary object

                d_dict = eval(d_str)

    #print(d_dict)
    #  print(d_dict2)

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
DS = digitalsignature(Identity+str(pubKeys), privKey)

certificate = {
    "Key": pubKeys,
    "Identity": "A",
    "messagetype": "certA",
    "DigitalSignature": DS

}
####

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
