import select
import socket
import threading
import time
from threading import Event
import rsa
import ast
import hashlib
import random

HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

pubKeyS = rsa.PublicKey(8368535986424301519677425007078978282009409033444347711859615499370048341703074655505522462102048766899036091098557433327396428069258465008565662942145717, 65537)
privKeyS = rsa.PrivateKey(8368535986424301519677425007078978282009409033444347711859615499370048341703074655505522462102048766899036091098557433327396428069258465008565662942145717, 65537, 6652230812346619649497461482350221288425807910131936744084082717475350382459383323752051550397378681633251414741039522254878998390999853774646427340032513, 7565317343113682473003719157066451814412526235676237417376197496664743312864051731, 1106171176552395053279328787437653065548540673055795968788597324959395607)

# 3. The Chat Server, S, has access to all Entity Certificates that use its service and can provide these Certificate to its
#service users if requested to do so.
certA = {
    "messagetype": "certA",
    "publicKey": None
}
certB = {
    "messagetype": "certB",
    "publicKey": None
}
certC = {
    "messagetype": "certC",
    "publicKey": None
}
##this should be got from when A sends cert originally
NonceA1 = 0
NonceB1 = 0
NonceC1 = 0
Nonce1=0
##this is S nonce which IS created dynamically
#
NonceS = random.randint(0, 2**64-1)


SAuthA = {
    'messagetype': 'SAuthA',
    'NonceA1&S': '',
    'DSA': ''
}
SAuthB = {
    "messagetype": "SAuthB",
    "NonceB1&S": "",
    "DSB": ""
}
SAuthC = {
    "messagetype": "SAuthC",
    "NonceC1&S": "",
    "DSC": ""
}

SharedAuth = {
    'AB':'',
    'AC':'',
    'BA':'',
    'BC':'',
    'CA':'',
    'CB':''

}
MessagesDict = {}

####FUNCTIONS FOR THE OPERATIONS
def hash(message):
    # Create a hash object with the specified algorithm
    hash_object = hashlib.new("sha256")
    # Update the hash object with the input string encoded as bytes
    hash_object.update(message.encode())
    # Get the hexadecimal representation of the hash
    hash_hex = hash_object.hexdigest()
    return hash_hex

def encrypt(msgencrypt, key):
    message = msgencrypt.encode(FORMAT)
    msgencrypt = rsa.encrypt(message, key)
    return msgencrypt


def decrypt(msgdecrypt, key):
    msgdecrypt = rsa.decrypt(msgdecrypt, key)
    msgdecrypt = msgdecrypt.decode(FORMAT)
    return msgdecrypt

##this creates the DS
##signs message with key you specified
##uses sha-256 for hash
def digitalsignature(msgSign, key):
    msgSign = msgSign.encode(FORMAT)
    msgSign = rsa.sign(msgSign, key, 'SHA-256')
    return msgSign

##verifys message
##encrypts and hashes message and checks if
#it equals signature
def verifyDS(msgVerify, signature, key):
    msgVerify = msgVerify.encode(FORMAT)
    msgVerify = rsa.verify(msgVerify, signature, key)
    if msgVerify == 'SHA-256':
        true = 'true'
        return true
    else:
        false ='false'
        return false


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
            if msg == DISCONNECT_MESSAGE:
                connected = False

            print(f"[{addr}] {msg}")


            ##recieving certificate
            try:
                res = eval(msg)
                cert = 'true'
            except:
                cert = 'false'
                pass

            if cert == 'true':
                messagetype = res['messagetype']

                key2 = rsa.PublicKey(res['Key'][0], res['Key'][1])
                identity = res['Identity']
                DS = res['DigitalSignature']
                NONCE1 = res['Nonce1']

                #CHALLENGE S RECIEVES IT STORES IT, TO RESPOND LATER
                NONCE1 = decrypt(NONCE1, privKeyS)
                NONCE1 = int(NONCE1)

                ###this is S verifying what it recieved from A
                # 4. Each step in establishing the Session key (Kabc) must provide an Authenticated Integrity check of the data
                # transferred. You must show both sides of this in your protocol design and description, i.e. its generation and
                # how it is checked.

                verification = verifyDS(identity+str(key2), DS, key2)
                if verification == 'true':

                    # 3. The Chat Server, S, has access to all Entity Certificates that use its service and can provide these Certificate to its
                    # service users if requested to do so.
                    storeCerts(res)

                    #this stores the nonces and encrypts them in SAuthA
                    storeNonce(res, NONCE1)

                    #CREATING DIGITAL SIGNATURE WITH CHALLENGE WE RECIEVED AND THE CHALLENGE WE WILL SEND BACK
                    DSA = digitalsignature(str(NONCE1), privKeyS)
                    DSA2 = digitalsignature(str(NonceS), privKeyS)

                    #HERE WE FOMAT RESPONSE TO A AND SEND IT
                    if messagetype == "certA":
                        SAuthA.update({'DSA': (DSA, DSA2)})
                        conn.send(str(SAuthA).encode(FORMAT))
                        split = "split"
                        conn.send(split.encode(FORMAT))

                    elif  messagetype == "certB":
                        SAuthB.update({'DSB': (DSA, DSA2)})
                        conn.send(str(SAuthB).encode(FORMAT))
                        split = "split"
                        conn.send(split.encode(FORMAT))

                    elif  messagetype == "certC":
                        SAuthC.update({'DSC': (DSA, DSA2)})
                        conn.send(str(SAuthC).encode(FORMAT))
                        split = "split"
                        conn.send(split.encode(FORMAT))



            #A sends back nonce to server here so we must verify
            msg_length = conn.recv(HEADER).decode(FORMAT)

            if msg_length:
                msg_length = int(msg_length)

            VerifyingNonce = conn.recv(2048).decode(FORMAT)

            #eval to go from string to dict
            VerifyingNonce = eval(VerifyingNonce)

            #this verifys that Client sends correct nonce back to S
            verification = verifyDS(str(NonceS), VerifyingNonce['DSNonceS'], key2)


            while verification == 'true':

                #NOW WE SEE IF THE SERVER HAS THE OTHER CERTS IF IT DOESN'T WE WAIT
                if identity == 'A' and (certB['publicKey'] == None or certC['publicKey'] == None):
                      #  while (certB['publicKey'] == None or certC['publicKey'] == None):
                         time.sleep(5)
                         print("****WAITING*****!!!!!!!!!")

                ##IF IT DOES WE SEND THEM OUT
                elif identity == 'A' and (certB['publicKey'] != None and certC['publicKey'] != None):

                        conn.send(str(certB).encode(FORMAT))

                        stringtoSend = str(certC)

                        conn.send(stringtoSend.encode(FORMAT))
                        break

                if identity == 'B' and (certA['publicKey'] == None or certC['publicKey'] == None):
                            time.sleep(5)
                            print("****WAITING*****!!!!!!!!!")

                elif identity == 'B'and (certA['publicKey'] != None and certC['publicKey'] != None):


                     conn.send(str(certA).encode(FORMAT))

                     stringtoSend = str(certC)

                     conn.send(stringtoSend.encode(FORMAT))
                     break

                if identity == 'C' and (certA['publicKey'] == None or certB['publicKey'] == None):

                    time.sleep(5)
                    print("****WAITING*****!!!!!!!!!")

                elif identity == 'C'and (certA['publicKey'] != None and certB['publicKey'] != None):
                        conn.send(str(certA).encode(FORMAT))
                        stringtoSend = str(certB)
                        conn.send(stringtoSend.encode(FORMAT))
                        break

            #THIS IS WHERE MESSAGES ARE RECIEVED FROM A LETS SAY AND THEN FORWARDED TO B & C
            #FOR WHEN THE CLIENTS ARE AUTHENTICATING AND SWAPPING KEYS
            while connected:
                msgtoforward = conn.recv(2048).decode(FORMAT)
                msgtoforward1 = msgtoforward.split("split")[0]
                msgtoforward2 = msgtoforward.split("split")[1]
                ##GOES TO FORWARD FUNCTION TO BE STORED
                msgtorecieve1, msgtorecieve2 = forward(msgtoforward1, msgtoforward2, identity)

                #THESE THEN ARE THE MESSAGES FROM OTHER CLIENTS FOR YOU
                conn.send(str(msgtorecieve1).encode(FORMAT))
                conn.send(str(msgtorecieve2).encode(FORMAT))

                break


        #FUNCTION FOR FORWARDING AES COMMUNICATIONS
        i = 0
        while connected:
                  i += 1
                  message = conn.recv(2048)

                  if message:
                     # Update the dictionary with the received message
                     MessagesDict[str(identity)+str(i)] = message

                     conn.send(str(MessagesDict).encode(FORMAT))



    conn.close()


def forward(msg1, msg2 , identity):

    #eval to go from string to dict
    msg1 = eval(msg1)
    msg2 = eval(msg2)


    # Sends other identity messages if they are present
    other_identities = ['A', 'B', 'C']
    other_identities.remove(identity)
    identity1 = identity + other_identities[0]
    SharedAuth.update({identity1: msg1})
    identity2 = identity + other_identities[1]
    SharedAuth.update({identity2: msg2})

        #WAITS FOR DICT TO FILL WITH VALUES FROM OTHER THREADS
        # THEN WHEN IT DOES IT RETURNS THE MESSAGES FROM B AND C TO A (FOR EXAMPLE)
    while True:
        if SharedAuth['AB']!='' and SharedAuth['BA']!='' and SharedAuth['CA']!='':
            break
        else:
            time.sleep(1)
    other_identities[1] + identity
    msgtorecieve1 = SharedAuth[other_identities[0] + identity]
    msgtorecieve2 = SharedAuth[other_identities[1] + identity]

    value1 = msgtorecieve1
    value2 = msgtorecieve2

    return value1, value2

#STORES KEYS IN CERTS
# 3. The Chat Server, S, has access to all Entity Certificates that use its service and can provide these Certificate to its
#service users if requested to do so.
def storeCerts(cert):
    if cert['messagetype'] == "certA":
        key2 = rsa.PublicKey(cert['Key'][0], cert['Key'][1])
        certA.update({'publicKey': key2})

    elif cert['messagetype'] == "certB":
        key2 = rsa.PublicKey(cert['Key'][0], cert['Key'][1])
        certB.update({'publicKey': key2})

    elif cert['messagetype'] == "certC":
        key2 = rsa.PublicKey(cert['Key'][0], cert['Key'][1])
        certC.update({'publicKey': key2})


#STORES NONCE THAT S NEEDS TO RESPOND TO CHALLENGE FROM CLIENT
def storeNonce(cert, NonceX):
    if cert['messagetype'] == "certA":
        #FOR RESPONSE
        eNonceX = encrypt(str(NonceX), certA['publicKey'])
        #FOR CHALLENGE
        eNonceS = encrypt(str(NonceS), certA['publicKey'])
        #UPDATE SAUTHA WITH NONCES TO SEND TO CLIENT
        SAuthA.update({'NonceA1&S': (eNonceX, eNonceS)})

    elif cert['messagetype'] == "certB":
        eNonceX = encrypt(str(NonceX), certB['publicKey'])
        eNonceS = encrypt(str(NonceS), certB['publicKey'])
        # Noncea1s = eNonceX +''+ eNonceS

        SAuthB.update({'NonceB1&S': (eNonceX, eNonceS)})

    elif cert['messagetype'] == "certC":
        eNonceX = encrypt(str(NonceX), certC['publicKey'])
        eNonceS = encrypt(str(NonceS), certC['publicKey'])
        # Noncea1s = eNonceX +''+ eNonceS

        SAuthC.update({'NonceC1&S': (eNonceX, eNonceS)})



def FormatMsg(msg):
    msg = msg.replace("'", "")
    msg = msg.replace(")", "")
    msg = msg.replace("(", "")
    msg = msg.replace("PublicKey", "")
    msg = msg.replace("Key", "")
    msg = msg.replace("Identity", "")
    msg = msg.replace("{", "")
    msg = msg.replace("}", "")
    msg = msg.replace(":", "")

    return msg



def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:

        ##1. A, B and C Never communicate directly.
        ## here we set up threads so they can all communicate with S at the same time
        # but they can't communicate directly with each other

        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


print("[STARTING] server is starting...")
start()

