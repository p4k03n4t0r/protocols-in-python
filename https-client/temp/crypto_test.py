# from cryptography import x509
from cryptography.hazmat.backends import default_backend

# from cryptography.hazmat.primitives import hashes, hmac
# from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, derive_private_key, SECP256R1, SECP384R1, SECP521R1, ECDH
# from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
# from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
# from cryptography.hazmat.primitives.asymmetric import padding
from crypto_example import hkdf_expand_label

import hmac
import hashlib


finished_key = hkdf_expand_label(
    b"a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814",
    b"finished",
    b"",
    32,
)
finished_key = b"ea84abd2ada0b5c64c0807a326b6fd94a9597e39ca6210607c0d3c8c76686571"
finished_hash = b"0cd9871cd7a164dce9fbc7f96c0f2978417dfc0c728a3f2096a7de210991a865"
verify_data = hmac.new(finished_key, None, hashlib.sha256)
verify_data.update(finished_hash)
verify_data = verify_data.digest()
# verify_data_hmac = hmac.HMAC(finished_key, hashes.SHA256(), backend=default_backend())
# verify_data_hmac.update(finished_hash)
# verify_data = verify_data_hmac.finalize()
print(verify_data)


def verify_certificate_signature(
    signature_to_verify, data, certificate, signature_algorithm
):
    server_public_key = certificate.public_key()

    if signature_algorithm in [b"\x04\x01", b"\x04\x03", b"\x08\x04", b"\x08\x09"]:
        signature_hashes = hashes.SHA256()
    elif signature_algorithm in [b"\x05\x01", b"\x05\x03", b"\x08\x05", b"\x08\x0a"]:
        signature_hashes = hashes.SHA384()
    elif signature_algorithm in [b"\x06\x01", b"\x06\x03", b"\x08\x06", b"\x08\x0b"]:
        signature_hashes = hashes.SHA512()
    else:
        raise Exception("Signature hash not supported: {}".format(signature_algorithm))

    if signature_algorithm in [b"\x04\x01", b"\x05\x01", b"\x06\x01"]:
        signature_padding = padding.PKCS1()
    elif signature_algorithm in [
        b"\x08\x04",
        b"\x08\x05",
        b"\x08\x06",
        b"\x08\x09",
        b"\x08\x0a",
        b"\x08\x0b",
    ]:
        signature_padding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=0
        )
    else:
        raise Exception(
            "Signature padding not supported: {}".format(signature_algorithm)
        )

    # if the verify fails an exception will be thrown
    server_public_key.verify(
        signature_to_verify,
        data,
        signature_padding,
        signature_hashes,
    )
    return


def hash_transcript(cipher_suite, transcript_bytes):
    # only one cipher suite doesn't use SHA256, all others use SHA256
    # TLS_AES_256_GCM_SHA384 (x13 x02)
    if cipher_suite == b"\x13\x02":
        digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
    else:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

    # we concat the handshake messages while we skip the record part of them (first five bytes)
    # see https://tools.ietf.org/html/rfc8446#section-4.4.1
    concat = b""
    for i in range(len(transcript_bytes)):
        concat += transcript_bytes[i]
    digest.update(concat)
    return digest.finalize()


cipher_suite = b"\x13\x01"
server_signature = b"\x17\xfe\xb5\x33\xca\x6d\x00\x7d\x00\x58\x25\x79\x68\x42\x4b\xbc\x3a\xa6\x90\x9e\x9d\x49\x55\x75\x76\xa5\x20\xe0\x4a\x5e\xf0\x5f\x0e\x86\xd2\x4f\xf4\x3f\x8e\xb8\x61\xee\xf5\x95\x22\x8d\x70\x32\xaa\x36\x0f\x71\x4e\x66\x74\x13\x92\x6e\xf4\xf8\xb5\x80\x3b\x69\xe3\x55\x19\xe3\xb2\x3f\x43\x73\xdf\xac\x67\x87\x06\x6d\xcb\x47\x56\xb5\x45\x60\xe0\x88\x6e\x9b\x96\x2c\x4a\xd2\x8d\xab\x26\xba\xd1\xab\xc2\x59\x16\xb0\x9a\xf2\x86\x53\x7f\x68\x4f\x80\x8a\xef\xee\x73\x04\x6c\xb7\xdf\x0a\x84\xfb\xb5\x96\x7a\xca\x13\x1f\x4b\x1c\xf3\x89\x79\x94\x03\xa3\x0c\x02\xd2\x9c\xbd\xad\xb7\x25\x12\xdb\x9c\xec\x2e\x5e\x1d\x00\xe5\x0c\xaf\xcf\x6f\x21\x09\x1e\xbc\x4f\x25\x3c\x5e\xab\x01\xa6\x79\xba\xea\xbe\xed\xb9\xc9\x61\x8f\x66\x00\x6b\x82\x44\xd6\x62\x2a\xaa\x56\x88\x7c\xcf\xc6\x6a\x0f\x38\x51\xdf\xa1\x3a\x78\xcf\xf7\x99\x1e\x03\xcb\x2c\x3a\x0e\xd8\x7d\x73\x67\x36\x2e\xb7\x80\x5b\x00\xb2\x52\x4f\xf2\x98\xa4\xda\x48\x7c\xac\xde\xaf\x8a\x23\x36\xc5\x63\x1b\x3e\xfa\x93\x5b\xb4\x11\xe7\x53\xca\x13\xb0\x15\xfe\xc7\xe4\xa7\x30\xf1\x36\x9f\x9e"
server_certificate_bytes = open("temp/server.crt", "rb").read()
server_certificate = x509.load_pem_x509_certificate(
    server_certificate_bytes, default_backend()
)
server_signature_algorithm = b"\x08\x04"

dignital_signature = b"\x20" * 64
dignital_signature += b"TLS 1.3, server CertificateVerify"
dignital_signature += b"\x00"
# transcript_hash = hash_transcript(cipher_suite, transcript_bytes)
transcript_hash = b"3e66361ada42c7cb97f9a62b00cae1d8b584174c745f9a338cf9f7cdd51d15f8"
dignital_signature += transcript_hash

# verify signature
verify_certificate_signature(
    server_signature, dignital_signature, server_certificate, server_signature_algorithm
)
