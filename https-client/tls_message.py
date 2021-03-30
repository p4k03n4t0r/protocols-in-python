import random
import math

# An instance of this class represents a single message in a TLS connection
class TLS_Message:
    ENDINESS = "big"

    # TODO it's probably better if the enums are the other way around (key=hex, value=string) if we want to use them to pretty print the hex codes
    # TODO might be better to move the enums to a seperate class (or not...🙂)

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
        "TLS_AES_128_CCM_8_SHA256": b"\x13\x05",
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
        "tls1.3": b"\x03\04",
    }

    MESSAGE_TYPES = {
        "change_cipher_spec": b"\x14",
        "alert": b"\x15",
        "handshake": b"\x16",
        "application_data": b"\x17",
    }

    HANDSHAKE_TYPES = {
        "client_hello": b"\x01",
        "server_hello": b"\x02",
        "new_session_ticket": b"\x04",
        "end_of_early_data": b"\x05",
        "encrypted_extensions": b"\x08",
        "certificate": b"\x0b",
        "certificate_request": b"\x0d",
        "certificate_verify": b"\x0f",
        "finished": b"\x14",
        "key_update": b"\x18",
    }

    ALERT_LEVEL = {b"\x01": "warning", b"\x02": "fatal"}

    ALERT_DESCRIPTION = {
        b"\x00": "close_notify",
        b"\x0a": "unexpected_message",
        b"\x14": "bad_record_mac",
        b"\x15": "decryption_failed_RESERVED",
        b"\x16": "record_overflow",
        b"\x1e": "decompression_failure",
        b"\x28": "handshake_failure",
        b"\x29": "no_certificate_RESERVED",
        b"\x2a": "bad_certificate",
        b"\x2b": "unsupported_certificate",
        b"\x2c": "certificate_revoked",
        b"\x2d": "certificate_expired",
        b"\x2e": "certificate_unknown",
        b"\x2f": "illegal_parameter",
        b"\x30": "unknown_ca",
        b"\x31": "access_denied",
        b"\x32": "decode_error",
        b"\x33": "decrypt_error",
        b"\x3c": "export_restriction_RESERVED",
        b"\x46": "protocol_version",
        b"\x47": "insufficient_security",
        b"\x50": "internal_error",
        b"\x5a": "user_canceled",
        b"\x64": "no_renegotiation",
        b"\x6e": "unsupported_extension",
    }

    def __init__(self, message_type, message_version):
        self.ENDINESS = TLS_Message.ENDINESS
        self.server_name = None
        self.ciphers = []
        self.supported_groups = []
        self.signature_algorithms = []
        self.supported_versions = []
        self.public_keys = []
        if isinstance(message_type, str):
            if message_type not in self.MESSAGE_TYPES:
                raise Exception("Message type {} is not available".format(message_type))
            self.message_type = self.MESSAGE_TYPES[message_type]
        elif isinstance(message_type, bytes):
            self.message_type = message_type
        else:
            raise Exception("Message_type must either be a string or bytes")
        if isinstance(message_version, str):
            if message_version not in self.TLS_VERSIONS:
                raise Exception(
                    "Message version {} is not available".format(message_version)
                )
            self.message_version = self.TLS_VERSIONS[message_version]
        elif isinstance(message_version, bytes):
            self.message_version = message_version
        else:
            raise Exception("Message_version must either be a string or bytes")
        self.handshake_type = None
        self.session = None
        self.application_data = None
        self.key_exchange = None

    def generate_random(self):
        # generate random number which is 32 bytes long
        random_number = self.get_random_number(32)
        self.client_random = random_number.to_bytes(32, self.ENDINESS)

    def get_random_number(self, bytes_length):
        return random.randint(0, math.pow(math.pow(2, 8), bytes_length))

    def set_handshake_type(self, handshake_type_name):
        if handshake_type_name not in self.HANDSHAKE_TYPES:
            raise Exception(
                "Handshake type {} is not available".format(handshake_type_name)
            )
        self.handshake_type = self.HANDSHAKE_TYPES[handshake_type_name]

    def set_handshake_version(self, handshake_version_name):
        if handshake_version_name not in self.TLS_VERSIONS:
            raise Exception(
                "Handshake type {} is not available".format(handshake_version_name)
            )
        self.handshake_version = self.TLS_VERSIONS[handshake_version_name]

    def add_cipher(self, cipher_name):
        if cipher_name not in self.AVAILABLE_CIPHERS:
            raise Exception("Cipher {} is not available".format(cipher_name))
        self.ciphers.append(self.AVAILABLE_CIPHERS[cipher_name])

    def add_supported_group(self, supported_group_name):
        if supported_group_name not in self.AVAILABLE_SUPPORTED_GROUPS:
            raise Exception(
                "Supported group {} is not available".format(supported_group_name)
            )
        self.supported_groups.append(
            self.AVAILABLE_SUPPORTED_GROUPS[supported_group_name]
        )

    def add_signature_hash_algorithm(self, signature_hash_algorithm_name):
        if (
            signature_hash_algorithm_name
            not in self.AVAILABLE_HASH_SIGNATURE_ALGORITHMS
        ):
            raise Exception(
                "Signature hash algorithm {} is not available".format(
                    signature_hash_algorithm_name
                )
            )
        self.signature_algorithms.append(
            self.AVAILABLE_HASH_SIGNATURE_ALGORITHMS[signature_hash_algorithm_name]
        )

    def add_supported_version(self, supported_version_name):
        if supported_version_name not in self.TLS_VERSIONS:
            raise Exception(
                "Supported version {} is not available".format(supported_version_name)
            )
        self.supported_versions.append(self.TLS_VERSIONS[supported_version_name])

    def add_public_key(self, public_key, key_group_name):
        if key_group_name not in self.AVAILABLE_SUPPORTED_GROUPS:
            raise Exception(
                "Supported group {} is not available".format(key_group_name)
            )
        self.public_keys.append(
            {self.AVAILABLE_SUPPORTED_GROUPS[key_group_name]: public_key}
        )
