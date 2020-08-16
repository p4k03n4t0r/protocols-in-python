import base64
import hashlib

class Handshake:
    def __init__(self, data):
        split_data = data.replace("\r","").split("\n")
        # skip first line: GET / HTTP/1.1
        # skip last two lines: \n\n
        last_line = len(split_data)
        split_data = split_data[1:last_line - 2]
        self.headers = {}
        for i in range(len(split_data)):
            line = split_data[i]
            # split only on first occurence of ': '
            split_line = line.split(": ", 1)
            self.headers[split_line[0]] = split_line[1]


    def response(self):
        # build the Sec-WebSocket-Accept header if it's not calculated yet
        if "Sec-WebSocket-Accept" not in self.headers:
            # concatenate the client's Sec-WebSocket-Key and the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" together
            concat_string = "{}{}".format(self.headers["Sec-WebSocket-Key"], "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

            # take the SHA-1 hash of the concatenated string
            hash_object = hashlib.sha1(concat_string.encode('ascii'))
            hashed = hash_object.digest()

            # base64 encode the hash
            encoded = base64.b64encode(hashed)

            # set the result
            self.headers["Sec-WebSocket-Accept"] = encoded.decode('ascii')

        return "HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: {}\n\n".format(self.headers["Sec-WebSocket-Accept"])