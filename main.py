import socket
import threading
#import rsa



HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


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
            UserNumber = threading.activeCount() - 1
            splWord = ','
            key = msg.partition(splWord)[0]
            identity = msg.partition(splWord)[2]

            identity = FormatMsg(identity)
            key = FormatMsg(key)
            print(UserNumber)
            print("identity-->"+identity)
            print("key-->" +key)
            conn.send("Msg received".encode(FORMAT))

    conn.close()



def FormatMsg(msg):
    msg = msg.replace("'", "")
    msg = msg.replace(")", "")
    msg = msg.replace("(", "")
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