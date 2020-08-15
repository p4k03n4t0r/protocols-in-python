import hmac
import hashlib

# HMAC Key Derivation helper
# Used to derive from a crypthograpic key other cryptographically strong secret keys
class Hkdf_Helper:
    # documentation: https://tools.ietf.org/html/rfc5869
    # methods from: https://github.com/casebeer/python-hkdf/blob/master/hkdf.py

    @staticmethod
    def hdkf_extract(salt, input_key_material, hash_algorithm=hashlib.sha256):
        return hmac.new(salt, input_key_material, hash_algorithm).digest()

    @staticmethod
    def hkdf_expand(pseudo_random_key, info, length=32, hash_algorithm=hashlib.sha256):
        hash_len = hash_algorithm().digest_size
        length = int(length)
        if length > 255 * hash_len:
            raise Exception("Cannot expand to more than 255 * %d = %d bytes using the specified hash function" % (hash_len, 255 * hash_len))
        blocks_needed = length // hash_len + (0 if length % hash_len == 0 else 1) # ceil
        okm = b""
        output_block = b""
        for counter in range(blocks_needed):
            output_block = hmac.new(pseudo_random_key, output_block + info + bytearray((counter + 1,)), hash_algorithm).digest()
            okm += output_block
        return okm[:length]

    @staticmethod
    def hkdf_expand_label(pseudo_random_key, label, context, length=32, hash_algorithm=hashlib.sha256):
        # create info:
        # struct {
        #     uint16 length = Length;
        #     opaque label<7..255> = "tls13 " + Label;
        #     opaque context<0..255> = Context;
        # } HkdfLabel;
        # opaque: the actual length precedes the vector's contents in the byte stream
        label = b"tls13 " + label
        hkdf_label = length.to_bytes(2, 'big') + len(label).to_bytes(1, 'big') + label + len(context).to_bytes(1, 'big') + context
        return Hkdf_Helper.hkdf_expand(pseudo_random_key, hkdf_label, length, hash_algorithm)

    @staticmethod
    def hkdf_extract_expand_label(salt, input_key_material, label, context, length=32, hash_algorithm=hashlib.sha256):
        extract_result = Hkdf_Helper.hdkf_extract(salt, input_key_material, hash_algorithm)
        return Hkdf_Helper.hkdf_expand_label(extract_result, label, context, length, hash_algorithm)