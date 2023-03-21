import socket
import rsa

###test

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


def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    ####this is the recieved message
    recievingMessage = client.recv(2048).decode(FORMAT)
    print("recieved message=" + recievingMessage)
    #print(client.recv(2048).decode(FORMAT))



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
print("encrypted message-->" + str(encrypt(certificate['Identity'], certificate['Key'])))

#decrypt
encryptedText = encrypt(certificate['Identity'], certificate['Key'])
print("decrypted message-->" + str(decrypt(encryptedText, privKey)))

#digital signature
print("Digital Signature-->" + str(digitalsignature(certificate['Identity']+str(certificate['Key']), privKey)))
digitalSignature = digitalsignature(certificate['Identity']+str(certificate['Key']), privKey)

##verify digital signature
#it returns true if it verifys it and false if it doesn't
print(verifyDS(certificate['Identity']+str(certificate['Key']), digitalSignature, pubKeys))

input()
send(DISCONNECT_MESSAGE)
