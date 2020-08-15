from crypto_helper import Crypto_Helper
from tls_message import TLS_Message
from tls_message_packer import TLS_Message_Packer
from tls_message_unpacker import TLS_Message_Unpacker

# An instance of this class is used to initiate a TLS 1.3 handshake as a client with a server and a successful handshake send/receive encrypted messages
class TLS_Connection:
    def __init__(self, socket):
        self.socket = socket
        self.ENDINESS = "big"
        # init some values to None
        self.server_shared_key = None
        self.cryptographic_group = None
        self.client_private_key = None
        self.transcript_bytes = []
        self.cipher_suite = None
        self.handshake_done = False
        self.client_handshake_key = None
        self.client_handshake_iv = None
        self.counter = None

    def send(self, message):
        # we also send the client handshake key and iv and counter, because it might be needed to encrypt and wrap the message
        message_bytes = TLS_Message_Packer.pack_tls_message(message, self.client_handshake_key, self.client_handshake_iv, self.counter)
        if message.message_type == b"\x16":
            # TODO check if this is right
            self.transcript_bytes.append(message_bytes)
        # If the send message is application data (x17) we increment the counter
        if message.message_type == b"\x17":
            self.counter += 1
        print("SENDING: 📤")
        print(message_bytes)
        self.socket.send(message_bytes)

    def receive(self):
        print("RECEIVING: 📥")
        raw_message = b""

        # receive the message type
        message_type_bytes = self.socket.recv(1)
        raw_message += message_type_bytes

        # receive the message TLS version
        message_version_bytes = self.socket.recv(2)
        raw_message += message_version_bytes

        # receive the length of message and the message itself using this length
        record_length_bytes = self.socket.recv(2)
        record_length = int.from_bytes(record_length_bytes, self.ENDINESS)
        raw_message += record_length_bytes
        raw_content = self.socket.recv(record_length)
        raw_message += raw_content

        tls_message = TLS_Message_Unpacker.unpack_tls_message(message_type_bytes, message_version_bytes, record_length_bytes, raw_content)
        print(raw_message)
        if self.session != tls_message.session:
            raise Exception("Session id doesn't match!")

        # alert (x15/21)
        if tls_message.message_type == b"\x15":
            print("Alert")
            # parse back the binary value to the string value so we can print it 
            level_message = TLS_Message.ALERT_LEVEL[tls_message.level]
            description_message = TLS_Message.ALERT_DESCRIPTION[tls_message.description]
            print("Level: {}, Description: {}".format(level_message, description_message))
            # TODO handshake should only be stopped for level fatal
            raise Exception("Alert received, halting handshake")
   
        # application_data (x17/23)
        if tls_message.message_type == b"\x17":
            server_response_raw = self.decrypt_response(tls_message.application_data, tls_message.additional_data)
            # the decrypted Application Data is actually a Handshake message (https://tools.ietf.org/html/rfc8446#section-4)
            # we parse the application data as a Handshake message and set it as server_response
            tls_message = TLS_Message_Unpacker.parse_application_data(server_response_raw)
            self.counter += 1

        # handshake (x16/22)
        if tls_message.message_type == b"\x16":
            # save all Handshake messages, because we'll need it for calculating the keys
            self.transcript_bytes.append(raw_message)
        
        return tls_message

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
        if len(self.transcript_bytes) == 0:
            raise Exception("length of the transcript should be longer than 0")
        transcript_bytes = self.transcript_bytes
        if self.cipher_suite is None:
            raise Exception("cipher_suite must be set to calculate the keys!")
        cipher_suite = self.cipher_suite

        transcript_hash = Crypto_Helper.hash_transcript(cipher_suite, transcript_bytes)

        # 3) Key derivation and checking using specified cipher 
        # gives back 4 keys back based on the shared secret, these 4 keys will be used to encrypt/decrypt messages to/from the server 
        self.client_handshake_key, self.server_handshake_key, self.client_handshake_iv, self.server_handshake_iv = Crypto_Helper.derive_keys(cipher_suite, self.shared_secret, transcript_hash)
        print(b"client_handshake_key: " + self.client_handshake_key)
        print(b"server_handshake_key: " + self.server_handshake_key)
        print(b"client_handshake_iv: " + self.client_handshake_iv)
        print(b"server_handshake_iv: " + self.server_handshake_iv)

        # we have the keys so the handshake is done, all messages afterwards will be encrypted
        self.handshake_done = True
        # we keep a counter, which must be incremented for each message send and received, needed for encrypting/decrypting messages
        self.counter = 0

    def decrypt_response(self, message, additional_data):
        # for now only support TLS_AES_128_GCM_SHA256
        # TLS_AES_128_GCM_SHA256 (x13 x01)
        if self.cipher_suite != b"\x13\x01":
            raise Exception("Only cipher suite TLS_AES_128_GCM_SHA256 is supported for now") 

        # use the key/iv from the calculate_keys() function 
        server_handshake_key = self.server_handshake_key
        server_handshake_iv = self.server_handshake_iv
        # use the counter indicating how many encrypted messages have been send/received
        counter = self.counter
        decrypted_message = Crypto_Helper.aead_decrypt(message, additional_data, server_handshake_key, server_handshake_iv, counter)
        return decrypted_message