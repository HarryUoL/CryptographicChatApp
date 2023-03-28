import socket
import threading
from threading import Event
import rsa
import ast

HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

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

            res = eval(msg)
            print("certA that is stored-->")
            storeCerts(res)
            # print(certA)
            messagetype = res['messagetype']
            key = res['Key'][0]
            identity = res['Identity']
            print("message type-->" + messagetype)
            print("identity-->" + identity)
            print("key-->" + str(key))
            #conn.send("Msg received".encode(FORMAT))
            #testing with cert A
            # we need to send the two certs of the others we are not talking to rn




            ### for example with A while cert b and c are empty wait
            ##if its cert a or b or c then while the other two are empty wait
            #event.set()
            #event.clear()
            #event.wait()
            event = Event()
            event.set()

        if identity == 'A' and (certB['publicKey'] == None or certC['publicKey'] == None):
              #  while (certB['publicKey'] == None or certC['publicKey'] == None):
                    event.clear()
                    print("****WAITING*****!!!!!!!!!")
                    event.wait()
                    event.set()
        elif identity == 'A' and (certB['publicKey'] != None and certC['publicKey'] != None):
                print("THIS SHOULD BE CERT B-->" + str(certB))
                conn.send(str(certB).encode(FORMAT))
                split = "split"
                conn.send(split.encode(FORMAT))
                conn.send(str(certC).encode(FORMAT))



        if identity == 'B' and (certA['publicKey'] == None or certC['publicKey'] == None):

                    event.clear()
                    print("****WAITING*****!!!!!!!!!")
                    event.wait()
                    event.set()
        elif identity == 'B'and (certA['publicKey'] != None and certC['publicKey'] != None):
             conn.send(str(certA).encode(FORMAT))
             conn.send(str(certC).encode(FORMAT))

        if identity == 'C' and (certA['publicKey'] == None or certB['publicKey'] == None):

                    event.clear()
                    print("****WAITING*****!!!!!!!!!")
                    event.wait()
                    event.set()

        elif identity == 'C'and (certA['publicKey'] != None and certB['publicKey'] != None):
                conn.send(str(certA).encode(FORMAT))
                conn.send(str(certB).encode(FORMAT))






    conn.close()



def storeCerts(cert):
    if cert['messagetype'] == "certA":
        certA.update({'publicKey': cert['Key']})

    elif cert['messagetype'] == "certB":
        certB.update({'publicKey': cert['Key']})

    elif cert['messagetype'] == "certC":
        certC.update({'publicKey': cert['Key']})







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