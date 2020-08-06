# pip3 install pynacl
from nacl.public import PrivateKey, PublicKey
# pip3 install pycryptodome
from Crypto.PublicKey import ECC

class Key_Generator:
    # For X25519 and X448, the contents of the public value are the byte
    # string inputs and outputs of the corresponding functions defined in
    # [RFC7748]: 32 bytes for X25519 and 56 bytes for X448.
    @staticmethod
    def generate_x25519_keys():
        PrivateKey.SEED_SIZE = 32
        PrivateKey.SIZE = 32
        PublicKey.SIZE = 32
        private_key = PrivateKey.generate()
        public_key = bytes(private_key.public_key)
        # the key we want to share already matches the right format
        shared_key = public_key
        return private_key.encode(), public_key, shared_key

    @staticmethod
    def generate_secpr1_keys(secrp1_type):
        if secrp1_type == "secp256r1":
            curve = "P-256"
            coordinate_byte_size = 32
        elif secrp1_type == "secp384r1":
            curve = "P-384"
            coordinate_byte_size = 48
        elif secrp1_type == "secp521r1":
            curve = "P-521"
            coordinate_byte_size = 66
        else:
            raise Exception("Unknown secpr1 type {}".format(secrp1_type))

        curve = ECC.generate(curve=curve)
        private_key = curve.export_key(format='DER')
        public_key = curve.public_key().export_key(format='DER')
        
        # The key must be shared in a specific format so we generate this for this curve
        # https://tlswg.org/tls13-spec/antoine_address/draft-ietf-tls-tls13.html#ecdhe-param
        # For secp256r1, secp384r1, and secp521r1, the contents are the serialized value of the following struct:
        # struct {
        #     uint8 legacy_form = 4;
        #     opaque X[coordinate_length];
        #     opaque Y[coordinate_length];
        # } UncompressedPointRepresentation;
        shared_key = b"\x04" + curve.pointQ.x.to_bytes(coordinate_byte_size) + curve.pointQ.y.to_bytes(coordinate_byte_size)
        return private_key, public_key, shared_key