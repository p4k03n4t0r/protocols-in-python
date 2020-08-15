from crypto_helper import Crypto_Helper
from tls_message import TLS_Message
from tls_message_receiver import TLS_Message_Receiver
from tls_message_packer import TLS_Message_Packer
from tls_message_parser import TLS_Message_Parser

class TLS_Connection:
    def __init__(self, socket):
        self.socket = socket
        # init some values to None
        self.server_shared_key = None
        self.cryptographic_group = None
        self.client_private_key = None
        self.transcript_bytes = []
        self.cipher_suite = None
        self.handshake_done = False

    def send(self, message, add_to_transcript = False):
        message_bytes = TLS_Message_Packer.pack(message)
        # if needed we append the bytes of the message to the transcript of this handshake
        if add_to_transcript:
            self.transcript_bytes.append(message_bytes)
        print("SENDING: 📤")
        print(message_bytes)
        self.socket.send(message_bytes)

        # TODO if the send message is application data (x17) we increment the counter
        # if self.handshake_done:
        #     # encrypt & send
        #     self.counter += 1
        #     # raise Exception("Can't send encrypted messages yet")

    def receive(self):
        print("RECEIVING: 📥")
        server_response, server_response_raw = TLS_Message_Receiver.receive(self.socket)
        print(server_response_raw)
        if self.session != server_response.session:
            raise Exception("Session id doesn't match!")

        # alert (x15/21)
        if server_response.message_type == b"\x15":
            print("Alert")
            # parse back the binary value to the string value so we can print it 
            level_message = TLS_Message.ALERT_LEVEL[server_response.level]
            description_message = TLS_Message.ALERT_DESCRIPTION[server_response.description]
            print("Level: {}, Description: {}".format(level_message, description_message))
            raise Exception("Alert received, halting handshake")
   
        # application_data (x17/23)
        if server_response.message_type == b"\x17":
            server_response_raw = self.decrypt_response(server_response.application_data, server_response.additional_data)
            # the decrypted Application Data is actually a Handshake message (https://tools.ietf.org/html/rfc8446#section-4)
            # we parse the application data as a Handshake message and set it as server_response
            server_response = TLS_Message_Parser.parse_application_data(server_response_raw)
            self.counter += 1

        # handshake (x16/22)
        if server_response.message_type == b"\x16":
            # save all Handshake messages, because we'll need it for calculating the keys
            self.transcript_bytes.append(server_response_raw)
        
        return server_response

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