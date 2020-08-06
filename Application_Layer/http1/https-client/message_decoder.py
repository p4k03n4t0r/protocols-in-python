# pip3 install pynacl
from nacl.public import PrivateKey, PublicKey, Box

class Message_Decoder:
    @staticmethod
    def decode_x25519(message, private_key, public_key):
        prk = PrivateKey(private_key)
        puk = PublicKey(public_key)
        box = Box(prk, puk)
        d = box.decrypt(message)
        return d