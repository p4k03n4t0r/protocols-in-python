from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode
from cryptography.hazmat.primitives import hashes

import hmac
import hashlib

hello_hash = bytes.fromhex("da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5")
shared_secret = bytes.fromhex("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624")
zero_salt = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")

# https://tools.ietf.org/html/rfc5869
def hdkf_extract(salt, input_key_material, hash_algorithm=hashlib.sha256):
    return hmac.new(salt, input_key_material, hash_algorithm).digest()

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
    return hkdf_expand(pseudo_random_key, hkdf_label, length, hash_algorithm)

def hkdf_extract_expand_label(salt, input_key_material, label, context, length=32, hash_algorithm=hashlib.sha256):
    extract_result = hdkf_extract(salt, input_key_material, hash_algorithm)
    return hkdf_expand_label(extract_result, label, context, length, hash_algorithm)

empty_hash = hashes.Hash(hashes.SHA256(), default_backend()).finalize()
derived_secret = hkdf_extract_expand_label(zero_salt, b"\x00"*32, b"derived", empty_hash)

handshake_secret = hdkf_extract(derived_secret, shared_secret)
client_handshake_traffic_secret = hkdf_expand_label(handshake_secret, b"c hs traffic", hello_hash)
server_handshake_traffic_secret = hkdf_expand_label(handshake_secret, b"s hs traffic", hello_hash)

client_handshake_key = hkdf_expand_label(client_handshake_traffic_secret, b"key", b"", 16)
client_handshake_iv = hkdf_expand_label(client_handshake_traffic_secret, b"iv", b"", 12)
server_handshake_key = hkdf_expand_label(server_handshake_traffic_secret, b"key", b"", 16)
server_handshake_iv = hkdf_expand_label(server_handshake_traffic_secret, b"iv", b"", 12)

# print("handshake_secret: " + handshake_secret.hex())
# print("client_handshake_traffic_secret: " + client_handshake_traffic_secret.hex())
# print("server_handshake_traffic_secret: " + server_handshake_traffic_secret.hex())
# print("client_handshake_key: " + client_handshake_key.hex())
# print("client_handshake_iv: " + client_handshake_iv.hex())
# print("server_handshake_key: " + server_handshake_key.hex())
# print("server_handshake_iv: " + server_handshake_iv.hex())
