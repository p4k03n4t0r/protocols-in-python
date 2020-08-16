import socket
from handshake import Handshake
from frame import Frame
import threading
import time
import os
from flask import Flask, request
import ssl
import sys
import signal

HOST = "0.0.0.0" 
WEBSERVER_PORT = 8080
SOCKET_PORT = 8081
app = Flask(__name__)
if os.environ.get('SECURE') is not None:
    SECURE = os.environ.get('SECURE') == "TRUE"
else:
    SECURE = True

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
            received_frame = Frame(self.conn)
            print("Received frame 📥")
            if received_frame.opcode == 8:
                print("Connection Close Frame received 👋")
                break
            if received_frame.opcode == 9:
                print("Ping Frame received 🏓")
                # after a Ping Frame we have to return a Pong Frame to indicate the connection is still working
                pong_frame = Frame.encode_pong_frame()
                print("Returning Pong Frame {} 🏓".format(pong_frame))
                self.conn.send(pong_frame)
            if received_frame.opcode == 10:
                print("Pong Frame received 🏓")
            else:
                print("With payload {} 💣".format(received_frame.payload))
                ListenThread.last_message = received_frame.payload
                return_frame = Frame.encode_frame("Thank you for your message: {}".format(received_frame.payload))
                self.conn.send(return_frame)
        self.conn.close()
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

    def exit(self):
        sys.exit()

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

def listen(sock):
    sock.bind((HOST, SOCKET_PORT))
    print("Bound to port 🚪")
    while True:
        print("Listening for connections 👂")
        sock.listen()
        global conn
        conn, addr = sock.accept()
        with conn:  
            print("Connection from {} 🔌".format(addr))
            handshake(conn)
            print("Handshake done 🤝")
            listen_thread = ListenThread(conn)
            server_thread = ServerThread(conn, app)

            while listen_thread.is_running:
                time.sleep(1) 
            
            # if it hasn't stopped yet, try to kill the flask process
            try:
                t = server_thread.thread
                signal.pthread_kill(t.ident, signal.SIGINT)
            except Exception: pass

if SECURE:  
    # TODO do this so wss also works
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # context.options |= ssl.PROTOCOL_TLS_SERVER
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    # context.options |= ssl.CERT_NONE
    # context.check_hostname = False
    context.load_cert_chain("domain.crt", "domain.key")
    # context.set_ciphers("")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    if SECURE:
        with context.wrap_socket(sock, server_side=True) as ssock:
            listen(ssock)
    else:
        listen(sock)