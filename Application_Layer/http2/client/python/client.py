from hyper import HTTP11Connection, HTTP20Connection
from hyper.contrib import HTTP20Adapter
import socket
import ssl
import requests

# conn = HTTP11Connection("localhost:8011")
# conn.request("GET", "/")
# resp = conn.get_response()
# print(resp.read())
# print(resp.status)

# conn = HTTP11Connection("localhost:8111", secure=True, verify=False)
# conn.request("GET", "/")
# resp = conn.get_response()
# print(resp.read())
# print(resp.status)

# conn = HTTP20Connection("localhost:8020")
# conn.request("GET", "/")
# resp = conn.get_response()
# print(resp.read())
# print(resp.status)

conn = HTTP20Connection("localhost:8120", secure=True, verify=False)
conn.request("GET", "/")
resp = conn.get_response()
print(resp.read())
print(resp.status)

# hostname = 'localhost'
# context = ssl.create_default_context()

# with socket.create_connection((hostname, 8120)) as sock:
#     with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#         print(ssock.version())

print("HTTP1.1")
resp = requests.get("http://127.0.0.1:8011")
print(resp.status_code)

print("HTTP1.1 over TLS")
resp = requests.get("https://localhost:8111", verify=False)
print(resp.status_code)

# print("HTTP2")
# resp = requests.get("http://localhost:8020")
# print(resp.status_code)

print("HTTP2 over TLS")
resp = requests.get("https://localhost:8120", verify=False)
print(resp.status_code)
