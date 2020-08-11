# pip3 install pycryptodome
from Crypto.PublicKey import ECC
# pip3 install cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption 
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, derive_private_key, SECP256R1, SECP384R1, SECP521R1, ECDH
from cryptography.hazmat.primitives import hashes
from hkdf_helper import Hkdf_Helper

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Crypto_Helper:
    ENDINESS = 'big'

    @staticmethod
    def generate_client_keys(cryptographic_group):
        if cryptographic_group == "x25519" or cryptographic_group == "x448":
            return Crypto_Helper.generate_x_curve_keys(cryptographic_group)
        elif cryptographic_group == "secp256r1" or cryptographic_group == "secp384r1" or cryptographic_group == "secp521r1":
            return Crypto_Helper.generate_secpr1_keys(cryptographic_group)

    @staticmethod
    def generate_x_curve_keys(x_curve_type):
        if x_curve_type == "x25519":
            private_key = X25519PrivateKey.generate()
        elif x_curve_type == "x448":
           private_key = X448PrivateKey.generate()
        else:
            raise Exception("Unknown x curve type {}".format(x_curve_type))
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_key_bytes = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
        public_key_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        return private_key_bytes, public_key_bytes, public_key_bytes

    @staticmethod
    def generate_secpr1_keys(secrp1_type):
        if secrp1_type == "secp256r1":
            curve = SECP256R1()
            coordinate_byte_size = 32
        elif secrp1_type == "secp384r1":
            curve = SECP384R1()
            coordinate_byte_size = 48
        elif secrp1_type == "secp521r1":
            curve = SECP521R1()
            coordinate_byte_size = 66
        else:
            raise Exception("Unknown secpr1 type {}".format(secrp1_type))

        private_key = generate_private_key(curve, default_backend())
        private_key_bytes = private_key.private_bytes(encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
        
        # The key must be shared in a specific format so we generate this for this curve
        # https://tlswg.org/tls13-spec/antoine_address/draft-ietf-tls-tls13.html#ecdhe-param
        # For secp256r1, secp384r1, and secp521r1, the contents are the serialized value of the following struct:
        # struct {
        #     uint8 legacy_form = 4;
        #     opaque X[coordinate_length];
        #     opaque Y[coordinate_length];
        # } UncompressedPointRepresentation;
        x = private_key.private_numbers().public_numbers.x
        y = private_key.private_numbers().public_numbers.y
        shared_key = b"\x04" + x.to_bytes(coordinate_byte_size, Crypto_Helper.ENDINESS) + y.to_bytes(coordinate_byte_size, Crypto_Helper.ENDINESS)
        return private_key_bytes, public_key_bytes, shared_key

    @staticmethod
    def get_public_key_from_shared_key(shared_key, cryptographic_group):
        # for x25519 and x448 we don't have to do anything
        if cryptographic_group == b"\x00\x1d" or cryptographic_group == b"\x00\x1e":
            return shared_key

        # for secpr1 the shared key again has this format:
        # struct {
        #     uint8 legacy_form = 4;
        #     opaque X[coordinate_length];
        #     opaque Y[coordinate_length];
        # } UncompressedPointRepresentation;
        shared_key = shared_key[1:len(shared_key)]
        # the size of x/y depends on the cryptographic group
        # secp256r1
        if cryptographic_group == b"\x00\x17":
            coordinate_byte_size = 32
            curve_name = "P-256"
        # secp384r1
        elif cryptographic_group == b"\x00\x18":
            coordinate_byte_size = 48
            curve_name = "P-384"
        # secp521r1
        elif cryptographic_group == b"\x00\x19":
            coordinate_byte_size = 66
            curve_name = "P-521"
        # retrieve x and y from the shared key and turn them into bytes
        xBin = shared_key[0:coordinate_byte_size]
        x = int.from_bytes(xBin, Crypto_Helper.ENDINESS, signed=False)
        yBin = shared_key[coordinate_byte_size:coordinate_byte_size+coordinate_byte_size]
        y = int.from_bytes(yBin, Crypto_Helper.ENDINESS, signed=False)
        # TODO find cryptography.hazmat alternative so we only have to use a single library
        ecc_curve = ECC.construct(curve=curve_name, point_x=x, point_y=y)
        return ecc_curve.public_key().export_key(format='DER')

    @staticmethod
    def get_shared_secret(client_private_key, server_public_key, cryptographic_group):
        # x25519 (x00 x1d)
        if cryptographic_group == b"\x00\x1d":
            private_key = X25519PrivateKey.from_private_bytes(client_private_key)
            public_key = X25519PublicKey.from_public_bytes(server_public_key)
            return private_key.exchange(public_key)
        # x448 (x00 x1e)
        elif cryptographic_group == b"\x00\x1e":
            private_key = X448PrivateKey.from_private_bytes(client_private_key)
            public_key = X448PublicKey.from_public_bytes(server_public_key)
            return private_key.exchange(public_key)
        # secp256r1 (x00 x17)
        elif cryptographic_group == b"\x00\x17":
            return Crypto_Helper.get_shared_secret_secpr1(client_private_key, server_public_key, SECP256R1)
        # secp384r1 (x00 x18)
        elif cryptographic_group == b"\x00\x18":
            return Crypto_Helper.get_shared_secret_secpr1(client_private_key, server_public_key, SECP384R1)
        # secp521r1 (x00 x19)
        elif cryptographic_group == b"\x00\x19":
            return Crypto_Helper.get_shared_secret_secpr1(client_private_key, server_public_key, SECP521R1)

    @staticmethod
    def get_shared_secret_secpr1(client_private_key, server_public_key, curve_class):
        client_private_key_int = int.from_bytes(client_private_key, Crypto_Helper.ENDINESS)
        private_key = derive_private_key(client_private_key_int, curve_class(), default_backend())
        server_public_key_int = int.from_bytes(client_private_key, Crypto_Helper.ENDINESS)
        public_key = derive_private_key(server_public_key_int, curve_class(), default_backend())
        return private_key.exchange(ECDH(), public_key)

    @staticmethod
    def hash_transcript(cipher_suite, client_hello_bytes, server_hello_bytes):
        # only one cipher suite doesn't use SHA256, all others use SHA256
        # TLS_AES_256_GCM_SHA384 (x13 x02)
        if cipher_suite == b"\x13\x02":
            digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
        else:
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

        # TODO maybe already concat all handshake messages in a 'transcript_raw' property and add method transcript_hash() (https://tools.ietf.org/html/rfc8446#section-4.4.1)
        # we concat the handshake messages (Client Hello, Server Hello) while we skip the record part of the Hello's (first five bytes)
        concat = client_hello_bytes[5:len(client_hello_bytes)] + server_hello_bytes[5:len(server_hello_bytes)]
        digest.update(concat)
        return digest.finalize()

    @staticmethod
    def derive_keys(cipher_suite, shared_secret, transcript_hash):
        # for now only support TLS_AES_128_GCM_SHA256
        # TLS_AES_128_GCM_SHA256 (x13 x01)
        if cipher_suite != b"\x13\x01":
            raise Exception("Only cipher suite TLS_AES_128_GCM_SHA256 is supported for now") 

        empty_hash = hashes.Hash(hashes.SHA256(), default_backend()).finalize()
        derived_secret = Hkdf_Helper.hkdf_extract_expand_label(b"\x00"*32, b"\x00"*32, b"derived", empty_hash)

        handshake_secret = Hkdf_Helper.hdkf_extract(derived_secret, shared_secret)
        client_handshake_traffic_secret = Hkdf_Helper.hkdf_expand_label(handshake_secret, b"c hs traffic", transcript_hash)
        server_handshake_traffic_secret = Hkdf_Helper.hkdf_expand_label(handshake_secret, b"s hs traffic", transcript_hash)

        client_handshake_key = Hkdf_Helper.hkdf_expand_label(client_handshake_traffic_secret, b"key", b"", 16)
        client_handshake_iv = Hkdf_Helper.hkdf_expand_label(client_handshake_traffic_secret, b"iv", b"", 12)
        server_handshake_key = Hkdf_Helper.hkdf_expand_label(server_handshake_traffic_secret, b"key", b"", 16)
        server_handshake_iv = Hkdf_Helper.hkdf_expand_label(server_handshake_traffic_secret, b"iv", b"", 12)

        return client_handshake_key, server_handshake_key, client_handshake_iv, server_handshake_iv

    @staticmethod
    def decrypt_message(message, additional_data, server_handshake_key, server_handshake_iv):
        cipher = Cipher(algorithms.AES(server_handshake_key), modes.GCM(server_handshake_iv, tag=additional_data), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.update(message)
        decrypted_message = decryptor.finalize()
        return decrypted_message