from message_decoder import Message_Decoder
from crypto_helper import Crypto_Helper

class TLS_Connection:
    def __init__(self):
        self.server_shared_key = None
        self.cryptographic_group = None
        self.client_private_key = None
        self.client_hello_bytes = None
        self.server_hello_bytes = None
        self.cipher_suite = None

    def calculate_keys(self):
        # 1) calculate the shared secret
        # https://tools.ietf.org/html/rfc7748
        if self.server_shared_key is None:
            raise Exception("server_shared_key must be set to calculate the keys!")
        if self.cryptographic_group is None:
            raise Exception("cryptographic_group must be set to calculate the keys!")
        # calculate the Server Public Key based on the received Shared Key and Cryptographic Group
        self.server_public_key = Crypto_Helper.get_public_key_from_shared_key(self.server_shared_key, self.cryptographic_group)
        if self.client_private_key is None:
            raise Exception("client_private_key must be set to calculate the keys!")
        self.shared_secret = Crypto_Helper.get_shared_secret(self.client_private_key, self.server_public_key, self.cryptographic_group)

        # 2) calculate hash transcript of the handshake so far
        if self.client_hello_bytes is None:
            raise Exception("client_hello_bytes must be set to calculate the keys!")
        if self.server_hello_bytes is None:
            raise Exception("server_hello_bytes must be set to calculate the keys!")
        client_hello_bytes = self.client_hello_bytes
        server_hello_bytes = self.server_hello_bytes
        if self.cipher_suite is None:
            raise Exception("cipher_suite must be set to calculate the keys!")
        cipher_suite = self.cipher_suite

        transcript_hash = Crypto_Helper.hash_transcript(cipher_suite, client_hello_bytes, server_hello_bytes)

        # 3) Key derivation and checking using specified cipher 
        # gives back 4 keys back based on the shared secret, these 4 keys will be used to encrypt/decrypt messages to/from the server 
        client_handshake_key, server_handshake_key, client_handshake_iv, server_handshake_iv = Crypto_Helper.derive_keys(cipher_suite, self.shared_secret, transcript_hash)
 
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
