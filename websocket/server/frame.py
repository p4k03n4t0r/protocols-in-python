# from: https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-------+-+-------------+-------------------------------+
#  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
#  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
#  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
#  | |1|2|3|       |K|             |                               |
#  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
#  |     Extended payload length continued, if payload len == 127  |
#  + - - - - - - - - - - - - - - - +-------------------------------+
#  |                               |Masking-key, if MASK set to 1  |
#  +-------------------------------+-------------------------------+
#  | Masking-key (continued)       |          Payload Data         |
#  +-------------------------------- - - - - - - - - - - - - - - - +
#  :                     Payload Data continued ...                :
#  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
#  |                     Payload Data continued ...                |
#  +---------------------------------------------------------------+
class Frame:
    ENDINESS = "big"

    def __init__(self, conn):
        # receive first two bytes to read the header
        data = conn.recv(2)
        header = int.from_bytes(data[0:2], Frame.ENDINESS)
        self.parse_header(header)
        # opcode 0 = Continuation Frame (not implemented yet)
        # opcode 8 = Connection Close Frame
        # opcode 9 = Ping Frame
        # opcode 10 = Pong Frame
        # for both we finished parsing, since there is no payload
        if (
            self.opcode == 0
            or self.opcode == 8
            or self.opcode == 9
            or self.opcode == 10
        ):
            return
        # if the given length in the header is 126, the actual length is in the next 2 bytes
        if self.payload_length == 126:
            data = conn.recv(2)
            self.payload_length = int.from_bytes(data[0:2], Frame.ENDINESS)
        # if the given length in the header is 127, the actual length is in the next 8 bytes
        elif self.payload_length == 127:
            data = conn.recv(8)
            self.payload_length = int.from_bytes(data[0:8], Frame.ENDINESS)

        # now we know the length of the message, so we can receive the rest
        # the length is: 4 (masking key) + length of payload
        data = conn.recv(4 + self.payload_length)
        i = 0

        # we check if the mask flag in header was set
        # this must be the case for client->server communication
        if self.mask != 1:
            raise Exception("Masking should be turned on")

        # next 4 bytes are the masking key
        self.masking_key = [data[i], data[i + 1], data[i + 2], data[i + 3]]
        i += 4

        # loop through the payload based on the given length
        self.payload = b""
        l = 0
        for j in range(self.payload_length):
            # read the byte
            b = data[i]
            i += 1
            # decode the byte by looping through the masking key and XOR'ing the byte with it
            c = b ^ self.masking_key[l]
            # increment counter by 1 and reset to 0 if it exceeds the masking key length
            l = (l + 1) % len(self.masking_key)
            # parse result to char
            self.payload += c.to_bytes(1, Frame.ENDINESS)

        # if the opcode is 1 convert the payload from bytes to text
        if self.opcode == 1:
            self.payload = self.payload.decode("ascii")

    def parse_header(self, header):
        #   0                   1
        #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        #  +-+-+-+-+-------+-+-------------+
        #  |F|R|R|R| opcode|M| Payload len |
        #  |I|S|S|S|  (4)  |A|     (7)     |
        #  |N|V|V|V|       |S|             |
        #  | |1|2|3|       |K|             |
        #  +-+-+-+-+-------+-+-------------+
        self.payload_length = header % pow(2, 7)
        header = header >> 7
        self.mask = header % pow(2, 1)
        header = header >> 1
        self.opcode = header % pow(2, 4)
        # if self.opcode is 0:
        #     raise Exception("Continuation Frames not implemented yet")
        header = header >> 4
        # ignore RSV1-3 for now, they are used for extensions
        header = header >> 3
        self.fin = header
        # if self.fin != 1:
        #     raise Exception("Continuation Frames not implemented yet")

    @staticmethod
    def encode_frame(payload):
        # opcode 1 indicates we sent Text Frame with a payload
        opcode = 1
        frame = Frame.encode_header_and_length(opcode, payload)
        # don't encode/mask the payload, since server->client shouldn't do that
        for i in range(len(payload)):
            frame += ord(payload[i]).to_bytes(1, Frame.ENDINESS)
        return frame

    @staticmethod
    def encode_header_and_length(opcode, payload):
        #   0                   1
        #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        #  +-+-+-+-+-------+-+-------------+
        #  |F|R|R|R| opcode|M| Payload len |
        #  |I|S|S|S|  (4)  |A|     (7)     |
        #  |N|V|V|V|       |S|             |
        #  | |1|2|3|       |K|             |
        #  +-+-+-+-+-------+-+-------------+
        if opcode == 1:
            # add payload length
            payload_length = len(payload)
            # if payload is longer than 4 bytes, set header to value 127
            # and create an extended payload length with size 8 bytes
            if payload_length > 65535:
                encoded_header = 127
                encoded_extended_payload_length = payload_length.to_bytes(
                    8, Frame.ENDINESS
                )
            # if payload is longer than 15 bits, set header to value 126
            # and create an extended payload length with size 2 bytes
            elif payload_length > 125:
                encoded_header = 126
                encoded_extended_payload_length = payload_length.to_bytes(
                    2, Frame.ENDINESS
                )
            else:
                encoded_header = payload_length
                encoded_extended_payload_length = b""
        elif opcode == 8 or opcode == 9 or opcode == 10:
            encoded_header = 0
            encoded_extended_payload_length = b""
        else:
            raise Exception("opcode {} not implemented yet".format(opcode))

        # add mask (off = 0, because server->client shouldn't be masked)
        encoded_header += 0 << 7
        # add opcode (opcode 1 = text)
        encoded_header += opcode << 8
        # add FIN (single message = 1)
        encoded_header += 1 << 15
        encode_header_and_length = encoded_header.to_bytes(2, Frame.ENDINESS)
        encode_header_and_length += encoded_extended_payload_length
        return encode_header_and_length

    @staticmethod
    def encode_close_frame():
        # opcode 8 indicates we sent a Close Frame
        opcode = 8
        frame = Frame.encode_header_and_length(opcode, None)
        return frame

    @staticmethod
    def encode_ping_frame():
        # opcode 9 indicates we sent a Pong Frame
        opcode = 9
        frame = Frame.encode_header_and_length(opcode, None)
        return frame

    @staticmethod
    def encode_pong_frame():
        # opcode 10 indicates we sent a Pong Frame
        opcode = 10
        frame = Frame.encode_header_and_length(opcode, None)
        return frame
