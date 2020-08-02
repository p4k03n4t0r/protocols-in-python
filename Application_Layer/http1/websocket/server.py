import socket
from handshake import Handshake
from frame import Frame
import threading
import time
from flask import Flask, request

HOST = "0.0.0.0" 
WEBSERVER_PORT = 8080
SOCKET_PORT = 8081
app = Flask(__name__)

# TODO
# implement frame concatenation (opcode 0 & fin 1 -> fin 0 means more frames will come with opcode 0 till last frame indicated by fin 1)
# fix opcode 8,9,10 should also be able to send and receive a payload

class ListenThread:
    last_message = None

    def __init__(self, conn):
        self.conn = conn
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True                            
        self.is_running = True
        thread.start()   

    def run(self):
        while True:
            print("Listening for frames 👂")
            received_frame = Frame(conn)
            print("Received frame 📥")
            if received_frame.opcode == 8:
                print("Connection Close Frame received 👋")
                break
            if received_frame.opcode == 9:
                print("Ping Frame received 🏓")
                # after a Ping Frame we have to return a Pong Frame to indicate the connection is still working
                pong_frame = Frame.encode_pong_frame()
                print("Returning Pong Frame {} 🏓".format(pong_frame))
                conn.send(pong_frame)
            if received_frame.opcode == 10:
                print("Pong Frame received 🏓")
            else:
                print("With payload {} 💣".format(received_frame.payload))
                ListenThread.last_message = received_frame.payload
                return_frame = Frame.encode_frame("Thank you for your message: {}".format(received_frame.payload))
                conn.send(return_frame)
        conn.close()
        print("Connection closed 👋")
        self.is_running = False

class ServerThread:
    def __init__(self, conn, app):
        self.conn = conn
        self.app = app
        thread = threading.Thread(target=self.app.run, args=(HOST, WEBSERVER_PORT))
        thread.daemon = True 
        self.thread = thread
        thread = thread                           
        thread.start()   

def handshake(conn):
    data = conn.recv(1024).decode("ascii")
    handshake = Handshake(data)
    response = handshake.response()
    conn.sendall(response.encode('ascii'))

@app.route('/send')
def send():
    global conn
    msg = request.args.get("msg")
    msg_frame = Frame.encode_frame(msg)  

    conn.send(msg_frame)

    return "Send!"

@app.route('/receive')
def receive():
    return ListenThread.last_message

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, SOCKET_PORT))
    print("Bound to port 🚪")
    while True:
        print("Listening for connections 👂")
        s.listen()
        conn, addr = s.accept()
        with conn:  
            print("Connection from {} 🔌".format(addr))
            handshake(conn)
            print("Handshake done 🤝")
            listen_thread = ListenThread(conn)
            server_thread = ServerThread(conn, app)

            while listen_thread.is_running:
                time.sleep(1)
                
            # TODO kill server_thread.thread