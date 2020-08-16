#!/usr/bin/env python3
import socket
import time
from http_message import Http_Message
import sys
import signal
import os

host_address = "0.0.0.0"
if "HOST_ADDRESS" in os.environ:
    host_address = os.environ['HOST_ADDRESS']
host_port = 8080
if "HOST_PORT" in os.environ:
    host_port = int(os.environ['HOST_PORT'])

total_match_chunked = True
if "TOTAL_MATCH_CHUNKED" in os.environ:
    if os.environ['TOTAL_MATCH_CHUNKED'] == "True":
        total_match_chunked = True
    elif os.environ['TOTAL_MATCH_CHUNKED'] == "False":
        total_match_chunked = False
    else:
        raise Exception("Value for TOTAL_MATCH_CHUNKED must be either 'True' or 'False'")

if "PROXY_TO_ADDRESS" in os.environ and "PROXY_TO_PORT" in os.environ:
    is_proxy = True
    proxy_to_address = os.environ['PROXY_TO_ADDRESS'] 
    proxy_to_port = int(os.environ['PROXY_TO_PORT'])
else:
    is_proxy = False

def signal_handler(sig, frame):
    global server_socket
    print("Received SIGINT so closing socket 🧦")
    server_socket.close()
    sys.exit(0)
 
signal.signal(signal.SIGINT, signal_handler)

def connection_has_data(conn):
    # check if the connection has data available straight away
    # MSG_PEEK makes sure the data is not removed
    if conn.recv(1, socket.MSG_PEEK):
        return True
    # check again after 1 second
    time.sleep(1)
    return conn.recv(1, socket.MSG_PEEK)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((host_address, host_port))
    print("Bound to port 🚪")
    while True:
        # if a connection is finished this loop will start again, by listening for a new connection
        print("Listening for connections 👂")
        server_socket.listen()
        received_connection, addr = server_socket.accept()
        with received_connection:
            print("Connection from {} 🔌".format(addr))
            # keep listening for messages, since multiple messages might be send via one connection
            while connection_has_data(received_connection):   
                print("----------------------------BEGIN MESSAGE----------------------------")
                try: 
                    http_message = Http_Message(received_connection, total_match_chunked)
                    print("Message received:")
                    print("{} {} {}".format(http_message.http_method, http_message.request_target, http_message.http_version))
                    for key in http_message.headers:
                        print("{}: {}".format(key, http_message.headers[key]))
                    if hasattr(http_message, "body"):
                        print(http_message.body)
                    
                    # if this server is configured as a proxy, proxy the calls to the server behind
                    if is_proxy:
                        # the proxy blocks calls to /flag and returns a 403
                        if http_message.request_target == "/flag":
                            http_response = http_message.get_response(403)
                        else:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
                                print("Proxying request {} to {}:{}".format(http_message.request_target, proxy_to_address, proxy_to_port))
                                proxy_socket.connect((proxy_to_address, proxy_to_port))
                                proxy_socket.sendall(http_message.raw.encode("ascii"))
                                proxy_socket.settimeout(1)
                                http_response = ""
                                # keep receiving until nothing is received for a second
                                try:
                                    while True:
                                        http_response += proxy_socket.recv(1).decode("ascii")
                                except socket.timeout: pass
                    else:
                        http_response = http_message.get_response(200)
                    print("Sending response:")
                    print(http_response)
                    received_connection.send(http_response.encode("ascii"))
                except Exception as e: 
                    print("Couldn't handle message 🔥", e.args)
                print("-----------------------------END MESSAGE-----------------------------")