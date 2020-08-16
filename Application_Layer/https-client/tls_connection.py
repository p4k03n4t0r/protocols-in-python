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

    def send(self, tls_message):
        # we also send the client handshake key and iv and counter, because it might be needed to encrypt and wrap the message
        message_bytes, transcript_message_bytes = TLS_Message_Packer.pack_tls_message(tls_message, self.client_handshake_key, self.client_handshake_iv, self.counter)
        self.update_transcript(tls_message, transcript_message_bytes, True)
        # If the send message is application data (x17) we increment the counter
        if tls_message.message_type == b"\x17":
            self.counter += 1
        print("SENDING: 📤")
        print(message_bytes)
        self.socket.send(message_bytes)

    def receive(self):
        print("RECEIVING: 📥")
        message_bytes = b""

        # receive the message type
        message_type_bytes = self.socket.recv(1)
        message_bytes += message_type_bytes

        # receive the message TLS version
        message_version_bytes = self.socket.recv(2)
        message_bytes += message_version_bytes

        # receive the length of message and the message itself using this length
        record_length_bytes = self.socket.recv(2)
        record_length = int.from_bytes(record_length_bytes, self.ENDINESS)
        message_bytes += record_length_bytes
        content_bytes = self.socket.recv(record_length)
        message_bytes += content_bytes

        tls_message = TLS_Message_Unpacker.unpack_tls_message(message_type_bytes, message_version_bytes, record_length_bytes, content_bytes)
        print(message_bytes)
        if self.session != tls_message.session:
            raise Exception("Session id doesn't match!")

        # alert (x15/21)
        if tls_message.message_type == b"\x15":
            print("Alert 🚨")
            # parse back the binary value to the string value so we can print it 
            level_message = TLS_Message.ALERT_LEVEL[tls_message.level]
            description_message = TLS_Message.ALERT_DESCRIPTION[tls_message.description]
            print("Level: {}, Description: {}".format(level_message, description_message))
            # TODO handshake should only be stopped for level fatal
            raise Exception("Alert received, halting handshake")

        # handshake (x16/22)
        if tls_message.message_type == b"\x16":
            self.update_transcript(tls_message, message_bytes, True)
   
        # application_data (x17/23)
        if tls_message.message_type == b"\x17":
            message_bytes = self.decrypt_response(tls_message.application_data, tls_message.additional_data)
            # the decrypted Application Data is actually a Handshake message (https://tools.ietf.org/html/rfc8446#section-4)
            # we parse the application data as a Handshake message and set it as server_response
            tls_message = TLS_Message_Unpacker.parse_application_data(message_bytes)
            self.update_transcript(tls_message, message_bytes, False)
            self.counter += 1

        return tls_message

    def update_transcript(self, tls_message, message_bytes, remove_record_header):
        # For concreteness, the transcript hash is always taken from the
        # following sequence of handshake messages, starting at the first
        # ClientHello and including only those messages that were sent:
        # ClientHello, HelloRetryRequest, ClientHello, ServerHello,
        # EncryptedExtensions, server CertificateRequest, server Certificate,
        # server CertificateVerify, server Finished, EndOfEarlyData, client
        # Certificate, client CertificateVerify, client Finished.
        # handshake (x16/22) or application_data (x17/23)
        if tls_message.message_type in [b"\x16", b"\x17"]:
                # "client_hello": b"\x01",
                # "server_hello": b"\x02",
                # "encrypted_extensions": b"\x08",
                # "certificate": b"\x0b",
                # "certificate_request": b"\x0d",
                # "certificate_verify": b"\x0f",
                # "finished": b"\x14",
            if tls_message.handshake_type in [b"\x01", b"\x02", b"\x08", b"\x0d", b"\x0b", b"\x0d", b"\x0f", b"\x14"]:
                if remove_record_header:
                    message_bytes = message_bytes[5:]
                self.transcript_bytes.append(message_bytes)
        pass

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

    def verify_certificate(self, server_signature_algorithm, server_signature):
        # The digital signature is then computed over the concatenation of:
        # -  A string that consists of octet 32 (0x20) repeated 64 times
        # -  The context string
        # -  A single 0 byte which serves as the separator
        # -  The content to be signed
        dignital_signature =  b"\x20"*64
        dignital_signature += b"TLS 1.3, client CertificateVerify"
        dignital_signature += b"\x00"
        transcript_hash = Crypto_Helper.hash_transcript(self.cipher_suite, self.transcript_bytes)
        dignital_signature += transcript_hash

        # verify signature
        Crypto_Helper.verify_certificate_signature(server_signature, dignital_signature, self.server_certificate, server_signature_algorithm)

        return