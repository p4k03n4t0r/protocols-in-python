from tls_message import TLS_Message
from http_response import Http_Response
import socket
from crypto_helper import Crypto_Helper
from tls_connection import TLS_Connection

# example handshakes:
# https://tools.ietf.org/html/rfc8448

def wrap_in_tls_13(socket, host):
    tls_connection = TLS_Connection(socket)

    # follows the flow described in: https://tools.ietf.org/html/rfc8446#section-2

    # STEP 1) Construct a Client Hello handshake message
    # TLS 1.0 protocol version for interoperability with earlier implementations
    client_hello_message = TLS_Message("handshake", "tls1.0")
    client_hello_message.set_handshake_type("Client_Hello")
    tls_connection.session = client_hello_message.session
    # Because middleboxes have been created and widely deployed that do not allow protocol versions that they do not recognize, 
    # the TLS 1.3 session must be disguised as a TLS 1.2 session. This field is no longer used for version negotiation and is hardcoded to the 1.2 version. 
    # Instead version negotiation is performed using the "Supported Versions" extension.
    client_hello_message.set_handshake_version("tls1.2")
    client_hello_message.server_name = host
    client_hello_message.generate_random()
    client_hello_message.add_cipher("TLS_AES_128_GCM_SHA256")
    client_hello_message.add_signature_hash_algorithm("ecdsa_secp256r1_sha256")
    client_hello_message.add_signature_hash_algorithm("ecdsa_secp384r1_sha384")
    client_hello_message.add_signature_hash_algorithm("ecdsa_secp521r1_sha512")
    client_hello_message.add_signature_hash_algorithm("ed25519")
    client_hello_message.add_signature_hash_algorithm("ed448")
    client_hello_message.add_signature_hash_algorithm("rsa_pss_pss_sha256")
    client_hello_message.add_signature_hash_algorithm("rsa_pss_pss_sha384")
    client_hello_message.add_signature_hash_algorithm("rsa_pss_pss_sha512")
    client_hello_message.add_signature_hash_algorithm("rsa_pss_rsae_sha256")
    client_hello_message.add_signature_hash_algorithm("rsa_pss_rsae_sha384")
    client_hello_message.add_signature_hash_algorithm("rsa_pss_rsae_sha512")
    client_hello_message.add_supported_version("tls1.3")
    # TODO for now we only support sending a single key per Client Hello, but TLS1.3 also allows sending multiple and the server choosing one of them
    # cryptographic_group = "x25519"
    cryptographic_group = "secp256r1"
    client_hello_message.add_supported_group(cryptographic_group)
    client_private_key, client_public_key, client_key_share = Crypto_Helper.generate_client_keys(cryptographic_group)
    tls_connection.client_public_key = client_public_key
    tls_connection.client_private_key = client_private_key
    client_hello_message.add_public_key(client_key_share, cryptographic_group)
    # pack the request and send
    # we save the Client Hello request, because we need it to calculate the transcript hash
    tls_connection.send(client_hello_message, True)


    # STEP 2) Receive Server Hello or Hello Client Retry handshake message
    server_response, server_response_raw = tls_connection.receive()
    # handshake (x16/22)
    if server_response.message_type != b"\x16":
        raise Exception("Expected a Server Hello or Hello Client Retry, but got {}".format(server_response.message_type))
    # if the response is a HelloRetryRequest this means the server is able to find an acceptable set of parameters but the ClientHello does not contain sufficient information to proceed with the handshake
    # it's kinda vague, but if the server handshake message doesn't contain a key exchange it's probably a Hello_Retry_Request
    if server_response.key_exchange is not None:
        print("Server_Hello")
        # retrieve information about the connection from the Server_Hello
        tls_connection.server_shared_key = server_response.key_exchange
        # the crypthographic group(curve) to use
        tls_connection.cryptographic_group = server_response.supported_group
        # the cipher suite to use
        tls_connection.cipher_suite = server_response.cipher_suite
        # the TLS version to use
        tls_connection.tls_version = server_response.supported_version
        # save the Server Hello in bytes, because we'll need it for calculating the keys
        tls_connection.transcript_bytes.append(server_response_raw)
        # -> this might be followed by a change cipher spec (but this doesn't add anything)
        # -> we can no calculate the keys with the response from the server
        tls_connection.calculate_keys()
        # -> all following messages afterwards are application data messages (x17) which will use the calculated keys to encrypt/decrypt 
    else:
        print("Hello_Retry_Request")
        # -> client must response with a new Client_Hello with same session id, but changed key_share based on content of Hello_Retry_Request
        # (this probably means generating a new key with a different algorithm)
        # -> next response should be a Server_Hello message
        # for now print the expected curve and quit
        print("Expected cryptographic group: {}".format(server_response.supported_group))
        # TODO send another Client Hello with a key using the expected cryptographic group 
        # note: check or hashing in calculate_keys() still works if a second Hello Client is send
        raise Exception("Hello_Retry_Request unimplemented")


    # STEP 3) We send a Change Cipher Spec message
    change_cipher_spec_message = TLS_Message("change_cipher_spec", "tls1.0")
    tls_connection.send(change_cipher_spec_message)


    # STEP 4) We receive a Change Cipher Spec message
    server_response, server_response_raw = tls_connection.receive()
    # change_cipher_spec (x14/20)
    if server_response.message_type != b"\x14":
        raise Exception("Expected a Change Cipher Spec, but got {}".format(server_response.message_type))


    # STEP 5) We receive some application data
    server_response, server_response_raw = tls_connection.receive()
    # application_data (x17/23)
    if server_response.message_type != b"\x17":
        raise Exception("Expected an Application Data, but got {}".format(server_response.message_type))
    print(server_response)

    return tls_connection

host = 'github.com'
# host = 'example.com'
port = 443

with socket.create_connection((host, port)) as sock:
    tls_connection = wrap_in_tls_13(sock, host)