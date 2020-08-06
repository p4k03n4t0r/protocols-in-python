# pip3 install pynacl
from nacl.public import PrivateKey
# pip3 install pycryptodome
# from Crypto.PublicKey import ECC
# pip3 install cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import subprocess


class Key_Generator:
    # For X25519 and X448, the contents of the public value are the byte
    # string inputs and outputs of the corresponding functions defined in
    # [RFC7748]: 32 bytes for X25519 and 56 bytes for X448.
    @staticmethod
    def generate_x25519_keys():
        # https://crypto.stackexchange.com/questions/71560/curve25519-by-openssl
        # openssl genpkey -algorithm x25519
        private_key = subprocess.check_output("openssl genpkey -algorithm x25519 -outform DER", shell=True)
        subprocess.call(b"echo " + private_key + b" > privkey.pem", shell=True)
        public_key = subprocess.check_output("openssl pkey -in privkey.pem -inform DER -pubout -outform DER", shell=True)
        subprocess.call("rm privkey.pem", shell=True)
        return private_key, public_key
        # private_key = PrivateKey.generate()
        # public_key = bytes(private_key.public_key)
        # return private_key.encode(), public_key
    
    # For secp256r1, secp384r1, and secp521r1, the contents are the serialized value of the following struct:
    # struct {
    #     uint8 legacy_form = 4;
    #     opaque X[coordinate_length];
    #     opaque Y[coordinate_length];
    # } UncompressedPointRepresentation;
    @staticmethod
    def generate_secp256r1_keys():
        # https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations
        subprocess.check_output("openssl ecparam -name prime256v1 -genkey -noout -out privkey.pem", shell=True)
        subprocess.check_output("openssl ec -in privkey.pem -pubout -out pubkey.pem", shell=True)
        return None, None
        # private_key = ec.generate_private_key(
        #     ec.SECP256R1, default_backend()
        # )
        # public_key = private_key.public_key()
        # b = private_key.private_bytes(encoding=serialization.Encoding.Raw,
        #     format=serialization.PrivateFormat.PKCS8,
        #     encryption_algorithm=serialization.NoEncryption())
        # return private_key.private_bytes(encoding=serialization.Encoding.Raw,
        #     format=serialization.PrivateFormat.PKCS8,
        #     encryption_algorithm=serialization.NoEncryption()), None
            
    # @staticmethod
    # def generate_secp256r1_keys():
    #     private_key = ECC.generate(curve='secp256r1')
    #     public_key = private_key.public_key()
    #     return private_key.export_key(format='DER'), public_key.export_key(format='DER')