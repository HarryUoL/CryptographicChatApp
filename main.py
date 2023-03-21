import socket
import threading
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

}
certB = {
    "messagetype": "certA",
}
certC = {
    "messagetype": "certA",
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
            conn.send(str(certA).encode(FORMAT))




    conn.close()



def storeCerts(cert):
    if cert['messagetype'] == "certA":
        certA.update({'publicKey': cert['Key']})

    elif cert['messagetype'] == "certB":
        certB.update({'publicKey': cert['Key']})

    elif cert['messagetype'] == "certB":
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