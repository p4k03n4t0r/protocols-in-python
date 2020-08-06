from message_decoder import Message_Decoder

class TLS_Connection:
    def __init__(self):
        self.server_shared_key = None
        self.cryptographic_group = None
        self.client_private_key = None

    def calculate_keys(self):
        if self.server_shared_key is None:
            raise Exception("server_shared_key must be set to calculate the keys!")
        if self.cryptographic_group is None:
            raise Exception("cryptographic_group must be set to calculate the keys!")
        # TODO calculate the public key based on shared_key and algorithm
        # for x25519 we don't have to do anything
        # for secpr1 we have to strip the first byte and calculate using x and y
        server_public_key = self.server_shared_key

        if self.client_private_key is None:
            raise Exception("client_private_key must be set to calculate the keys!")
        client_private_key = self.client_private_key

        # SHA256 hash of ClientHello and ServerHello

        # First, the client finds the shared secret, which is the result of the key exchange that allows the client and server to agree on a number. 
        # The client multiplies the server's public key with the client's private key using the curve25519() algorithm. 
        # Since this is the same shared secret calculated by the server in "Server Handshake Keys Calc", 
        # the rest of the calculation is identical and the same values are found.


    def decode(self, message):
        private_key = self.client_private_key
        public_key = self.server_public_key
        # x25519 (x00 x1d)
        if self.cryptographic_group == b"\x00\x1d":
            return Message_Decoder.decode_x25519(message, private_key, public_key)
        # secp256r1 (x00 x17)
        if self.cryptographic_group == b"\x00\x17":
            return Message_Decoder.decode_secp256r1(message, private_key, public_key)
        else:
            raise Exception("Can't decode this cryptographic group yet")
