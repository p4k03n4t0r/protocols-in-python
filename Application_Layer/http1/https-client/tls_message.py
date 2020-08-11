import random
import math
from tls_message_parser import TLS_Message_Parser

# Note: this TLS message class is constructed to work with TLS 1.3 only, which means some values are hardcoded to make this a TLS 1.3 message
# more info on: https://tools.ietf.org/html/rfc8446
class TLS_Message:
    ENDINESS = 'big'

    # Use 'openssl ciphers -V' for more info about ciphers and which one can be used for TLS 1.3
    # Cipher suite names follow the naming convention:
    # CipherSuite TLS_AEAD_HASH
    #   - TLS = The string "TLS"  
    #   - AEAD = The AEAD algorithm used for record protection
    #   - HASH = The hash algorithm used with HKDF   
    AVAILABLE_CIPHERS = {
        "TLS_AES_128_GCM_SHA256": b"\x13\x01",
        "TLS_AES_256_GCM_SHA384": b"\x13\x02",
        "TLS_CHACHA20_POLY1305_SHA256": b"\x13\x03",
        "TLS_AES_128_CCM_SHA256": b"\x13\x04",
        "TLS_AES_128_CCM_8_SHA256": b"\x13\x05"
    }

    # TODO for now only the ECDHE groups are supported except x448
    AVAILABLE_SUPPORTED_GROUPS = {
        # Elliptic Curve Groups (ECDHE)
        "secp256r1": b"\x00\x17",
        "secp384r1": b"\x00\x18",
        "secp521r1": b"\x00\x19",
        "x25519": b"\x00\x1D",
        "x448": b"\x00\x1E",
        # Finite Field Groups (DHE)
        "ffdhe2048": b"\x01\x00",
        "ffdhe3072": b"\x01\x01",
        "ffdhe4096": b"\x01\x02",
        "ffdhe6144": b"\x01\x03",
        "ffdhe8192": b"\x01\x04",
    }

    AVAILABLE_HASH_SIGNATURE_ALGORITHMS = {
        # RSASSA-PKCS1-v1_5 algorithms
        "rsa_pkcs1_sha256": b"\x04\x01",
        "rsa_pkcs1_sha384": b"\x05\x01",
        "rsa_pkcs1_sha512": b"\x06\x01",
        # ECDSA algorithms
        "ecdsa_secp256r1_sha256": b"\x04\x03",
        "ecdsa_secp384r1_sha384": b"\x05\x03",
        "ecdsa_secp521r1_sha512": b"\x06\x03",
        # RSASSA-PSS algorithms with public key OID rsaEncryption
        "rsa_pss_rsae_sha256": b"\x08\x04",
        "rsa_pss_rsae_sha384": b"\x08\x05",
        "rsa_pss_rsae_sha512": b"\x08\x06",
        # EdDSA algorithms
        "ed25519": b"\x08\x07",
        "ed448": b"\x08\x08",
        # RSASSA-PSS algorithms with public key OID RSASSA-PSS
        "rsa_pss_pss_sha256": b"\x08\x09",
        "rsa_pss_pss_sha384": b"\x08\x0a",
        "rsa_pss_pss_sha512": b"\x08\x0b",
        # Legacy algorithms
        "rsa_pkcs1_sha1": b"\x02\x01",
        "ecdsa_sha1": b"\x02\x03",
    }

    TLS_VERSIONS = {
        "tls1.0": b"\x03\01",
        "tls1.1": b"\x03\02",
        "tls1.2": b"\x03\03",
        "tls1.3": b"\x03\04"
    }

    MESSAGE_TYPES = {
        "change_cipher_spec": b"\x14",
        "alert": b"\x15",
        "handshake": b"\x16",
        "application_data": b"\x17"
    }

    HANDSHAKE_TYPES = {
        "Client_Hello": b"\x01",
        "Server_Hello": b"\x02"
    }

    ALERT_LEVEL = {
        "warning": b"\x01",
        "fatal": b"\x02"
    }

    ALERT_DESCRIPTION = {
        "close_notify": b"\x00",
        "unexpected_message": b"\x0a",
        "bad_record_mac": b"\x14",
        "decryption_failed_RESERVED": b"\x15",
        "record_overflow": b"\x16",
        "decompression_failure": b"\x1e",
        "handshake_failure": b"\x28",
        "no_certificate_RESERVED": b"\x29",
        "bad_certificate": b"\x2a",
        "unsupported_certificate": b"\x2b",
        "certificate_revoked": b"\x2c",
        "certificate_expired": b"\x2d",
        "certificate_unknown": b"\x2e",
        "illegal_parameter": b"\x2f",
        "unknown_ca": b"\x30",
        "access_denied": b"\x31",
        "decode_error": b"\x32",
        "decrypt_error": b"\x33",
        "export_restriction_RESERVED": b"\x3c",
        "protocol_version": b"\x46",
        "insufficient_security": b"\x47",
        "internal_error": b"\x50",
        "user_canceled": b"\x5a",
        "no_renegotiation": b"\x64",
        "unsupported_extension": b"\x6e"
    }
    
    def __init__(self, message_type_name = None, message_version_name = None):
        self.ENDINESS = TLS_Message.ENDINESS 
        self.server_name = None
        self.ciphers = []
        self.supported_groups = []
        self.signature_algorithms = []
        self.supported_versions = []
        self.public_keys = []
        if message_type_name != None:
            if message_type_name not in self.MESSAGE_TYPES:
                raise Exception("Message type {} is not available".format(message_type_name))
            self.message_type = self.MESSAGE_TYPES[message_type_name]
        if message_version_name != None:
            if message_version_name not in self.TLS_VERSIONS:
                raise Exception("Message version {} is not available".format(message_version_name))
            self.message_version = self.TLS_VERSIONS[message_version_name]
        self.handshake_type = None
        self.session = None
        self.application_data = None
        self.key_exchange = None

    @staticmethod
    def receive(socket):
        # also track and return the raw_message since we might need this later
        raw_message = b""
        tls_message = TLS_Message()

        # receive the message type
        data = socket.recv(1)
        tls_message.message_type = data
        raw_message += data

        # receive the message TLS version
        data = socket.recv(2)
        tls_message.message_version = data
        raw_message += data

        # receive the length of message and the message itself using this length
        data = socket.recv(2)
        record_length = int.from_bytes(data, TLS_Message.ENDINESS)
        raw_message += data
        raw_content = socket.recv(record_length)
        raw_message += raw_content
        print(raw_message)

        # Change Cipher Spec (x14/20) 
        if tls_message.message_type == b"\x14":
            # the Change Cipher Spec message doesn't have a body
            pass
        # Alert (x15/21)
        elif tls_message.message_type == b"\x15":
            TLS_Message_Parser.parse_alert(tls_message, raw_content)
        # Handshake (x16/22)
        elif tls_message.message_type == b"\x16":
            TLS_Message_Parser.parse_handshake(tls_message, raw_content)
        # Application Data (x17/23)
        elif tls_message.message_type == b"\x17":
            # the whole content is the application data
            tls_message.application_data = raw_content
            # additional data is a combination of the record fields of this package
            # see https://tools.ietf.org/html/rfc8446#section-5.2
            xor_result = int.from_bytes(tls_message.message_type, TLS_Message.ENDINESS) | int.from_bytes( tls_message.message_version, TLS_Message.ENDINESS) | record_length
            tls_message.additional_data = xor_result.to_bytes(16, TLS_Message.ENDINESS)
        else:
            raise Exception("Can't handle this message type yet")
        return tls_message, raw_message
        
    def generate_random(self):
        # generate random number which is 32 bytes long
        random_number = self.get_random_number(32)
        self.client_random = random_number.to_bytes(32, self.ENDINESS)

    def get_random_number(self, bytes_length):
        return random.randint(0, math.pow(math.pow(2, 8), bytes_length))

    def set_handshake_type(self, handshake_type_name):
        if handshake_type_name not in self.HANDSHAKE_TYPES:
            raise Exception("Handshake type {} is not available".format(handshake_type_name))
        self.handshake_type = self.HANDSHAKE_TYPES[handshake_type_name]

    def set_handshake_version(self, handshake_version_name):
        if handshake_version_name not in self.TLS_VERSIONS:
            raise Exception("Handshake type {} is not available".format(handshake_version_name))
        self.handshake_version = self.TLS_VERSIONS[handshake_version_name]

    def add_cipher(self, cipher_name):
        if cipher_name not in self.AVAILABLE_CIPHERS:
            raise Exception("Cipher {} is not available".format(cipher_name))
        self.ciphers.append(self.AVAILABLE_CIPHERS[cipher_name])

    def add_supported_group(self, supported_group_name):
        if supported_group_name not in self.AVAILABLE_SUPPORTED_GROUPS:
            raise Exception("Supported group {} is not available".format(supported_group_name))
        self.supported_groups.append(self.AVAILABLE_SUPPORTED_GROUPS[supported_group_name])

    def add_signature_hash_algorithm(self, signature_hash_algorithm_name):
        if signature_hash_algorithm_name not in self.AVAILABLE_HASH_SIGNATURE_ALGORITHMS:
            raise Exception("Signature hash algorithm {} is not available".format(signature_hash_algorithm_name))
        self.signature_algorithms.append(self.AVAILABLE_HASH_SIGNATURE_ALGORITHMS[signature_hash_algorithm_name])

    def add_supported_version(self, supported_version_name):
        if supported_version_name not in self.TLS_VERSIONS:
            raise Exception("Supported version {} is not available".format(supported_version_name))
        self.supported_versions.append(self.TLS_VERSIONS[supported_version_name])

    def add_public_key(self, public_key, key_group_name):
        if key_group_name not in self.AVAILABLE_SUPPORTED_GROUPS:
            raise Exception("Supported group {} is not available".format(key_group_name))
        self.public_keys.append({self.AVAILABLE_SUPPORTED_GROUPS[key_group_name]: public_key})