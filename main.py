import socket
import threading
import time
from threading import Event
import rsa
import ast
import hashlib

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
#key2 = rsa.PublicKey(res['Key'][0], res['Key'][1])
certA = {
    "messagetype": "certA",
    "publicKey": None
}
certB = {
    "messagetype": "certB",
    "publicKey": 2
}
certC = {
    "messagetype": "certC",
    "publicKey": 3
}
##this should be got from when A sends cert originally
NonceA1 = 3
##this is S nonce which needs to be created dynamically
NonceS = 5
#(NonceS,NonceA1)
#"NonceS&A1":
# "NonceS":

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
    'A':'',
    'B':'',
    'C':''

}
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


            ##test recieving certificate
            try:
                res = eval(msg)
                cert = 'true'
            except:
                cert = 'false'
                pass

            if cert == 'true':
                messagetype = res['messagetype']
                ###make sure nonce is stored
                ### Nonce1 = res['Nonce1']
                key2 = rsa.PublicKey(res['Key'][0], res['Key'][1])
                identity = res['Identity']
                DS = res['DigitalSignature']
                #print("cert that is stored-->")
                ###this is S verifying what it recieved from A
                verification = verifyDS(identity+str(key2), DS, key2)
                if verification == 'true':
                    storeCerts(res)

                    # ILL JUST SEND DUMMY ATM
                    # SENDS NONCE1 AND ITS OWN NONCE LETS SAY N2 ENCYPTED WITH PUBKEY OF A
                    # ASWELL AS ABOVE HASHED
                    ###ill have to change NonceA1 to res['nonce1'] or something 1 to identify its not a key a,b,c are keys then
                    ### i could add a way to store nonces in the store cert function???
                    ###probably have if statement here for identities???

                    #this stores the nonces and encrypts them in SAuthA
                    storeNonce(res, NonceA1)


                    ###store certs only done for A
                    ### i  need to ds NonceA1 and NonceS with private key of S
                    ### then add it to SAuthA

                    DSA = digitalsignature(str(NonceA1), privKeyS)
                    DSA2 = digitalsignature(str(NonceS), privKeyS)
                    SAuthA.update({'DSA': (DSA, DSA2)})

                    conn.send(str(SAuthA).encode(FORMAT))
                    split = "split"
                    conn.send(split.encode(FORMAT))


            #A sends back nonce of server here so we must verify
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
               # msg = conn.recv(2048).decode(FORMAT)
            VerifyingNonce = conn.recv(2048).decode(FORMAT)
            #eval to go from string to dict
            VerifyingNonce = eval(VerifyingNonce)
            #this verifys that Client sends correct nonce back to S
            verification = verifyDS(str(NonceS), VerifyingNonce['DSNonceS'], key2)

            ### for example with A while cert b and c are empty wait
            ##if its cert a or b or c then while the other two are empty wait
            #event.set()
            #event.clear()
            #event.wait()
            event = Event()
            event.set()

            if verification == 'true':
                if identity == 'A' and (certB['publicKey'] == None or certC['publicKey'] == None):
                      #  while (certB['publicKey'] == None or certC['publicKey'] == None):
                            event.clear()
                            print("****WAITING*****!!!!!!!!!")
                            event.wait()
                            event.set()
                elif identity == 'A' and (certB['publicKey'] != None and certC['publicKey'] != None):
                        print("THIS SHOULD BE CERT B-->" + str(certB))
                        conn.send(str(certB).encode(FORMAT))
                        #split = "split"
                        #conn.send(split.encode(FORMAT))
                        stringtoSend = str(certC)
                        #conn.send(split.encode(FORMAT) + str(certC).encode(FORMAT))
                        conn.send(stringtoSend.encode(FORMAT))


                if identity == 'B' and (certA['publicKey'] == None or certC['publicKey'] == None):

                            event.clear()
                            print("****WAITING*****!!!!!!!!!")
                            event.wait()
                            event.set()
                elif identity == 'B'and (certA['publicKey'] != None and certC['publicKey'] != None):
                     conn.send(str(certA).encode(FORMAT))
                     split = "split"
                     conn.send(split.encode(FORMAT))
                     conn.send(str(certC).encode(FORMAT))

                if identity == 'C' and (certA['publicKey'] == None or certB['publicKey'] == None):

                            event.clear()
                            print("****WAITING*****!!!!!!!!!")
                            event.wait()
                            event.set()

                elif identity == 'C'and (certA['publicKey'] != None and certB['publicKey'] != None):
                        conn.send(str(certA).encode(FORMAT))
                        split = "split"
                        conn.send(split.encode(FORMAT))
                        conn.send(str(certB).encode(FORMAT))


            while connected:
                msgtoforward = conn.recv(2048).decode(FORMAT)
                msgtoforward1, msgtoforward2 = msgtoforward.split("|")
                forward(msgtoforward1, msgtoforward2, identity)
                break



    conn.close()


def forward(msg1, msg2 , identity):

    #eval to go from string to dict
    msg1 = eval(msg1)
    msg2 = eval(msg2)
  #  if identity == 'A':
     #   SharedAuth.update(['A'], msg)

     # elif identity == 'B':
     #   SharedAuth.update(['B'], msg)

      #elif identity == 'C':
      #  SharedAuth.update(['C'], msg)
    SharedAuth.update({identity: msg1})
    SharedAuth.update({identity: msg2})
    # Send other identity messages if they are present
    other_identities = ['A', 'B', 'C']
    other_identities.remove(identity)

    while True:
        if SharedAuth['A']!='' and SharedAuth['B']!='' and SharedAuth['C']!='':
            break
        else:
            time.sleep(1)

    value1 = SharedAuth[other_identities[0]]
    value2 = SharedAuth[other_identities[1]]
    return value1, value2


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

##########################This needs to be changed when i have s keys##############################

def storeNonce(cert, NonceX):
    if cert['messagetype'] == "certA":

        eNonceX = encrypt(str(NonceX), certA['publicKey'])
        eNonceS = encrypt(str(NonceS), certA['publicKey'])
        #Noncea1s = eNonceX +''+ eNonceS

        SAuthA.update({'NonceA1&S': (eNonceX, eNonceS)})

    elif cert['messagetype'] == "certB":
        SAuthB.update({'NonceB1': NonceX})

    elif cert['messagetype'] == "certC":
        SAuthC.update({'NonceC1': NonceX})



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
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


print("[STARTING] server is starting...")
start()









