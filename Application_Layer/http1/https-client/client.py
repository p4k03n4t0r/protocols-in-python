from tls_message import TLS_Message
from tls_message_packer import TLS_Message_Packer
from http_response import Http_Response
import socket
from crypto_helper import Crypto_Helper
from tls_connection import TLS_Connection

# example handshakes:
# https://tools.ietf.org/html/rfc8448

HOST = 'github.com'
# HOST = 'example.com'
PORT = 443

tls_connection = TLS_Connection()

# follows the flow described in: https://tools.ietf.org/html/rfc8446#section-2
with socket.create_connection((HOST, PORT)) as sock:
    # construct a Client Hello handshake message
    # TLS 1.0 protocol version for interoperability with earlier implementations
    tls_message = TLS_Message("handshake", "tls1.0")
    tls_message.set_handshake_type("Client_Hello")

    tls_connection.session = tls_message.session
    
    # Because middleboxes have been created and widely deployed that do not allow protocol versions that they do not recognize, 
    # the TLS 1.3 session must be disguised as a TLS 1.2 session. This field is no longer used for version negotiation and is hardcoded to the 1.2 version. 
    # Instead version negotiation is performed using the "Supported Versions" extension.
    tls_message.set_handshake_version("tls1.2")
    tls_message.server_name = HOST
    tls_message.generate_random()
    tls_message.add_cipher("TLS_AES_128_GCM_SHA256")
    tls_message.add_signature_hash_algorithm("ecdsa_secp256r1_sha256")
    tls_message.add_signature_hash_algorithm("ecdsa_secp384r1_sha384")
    tls_message.add_signature_hash_algorithm("ecdsa_secp521r1_sha512")
    tls_message.add_signature_hash_algorithm("ed25519")
    tls_message.add_signature_hash_algorithm("ed448")
    tls_message.add_signature_hash_algorithm("rsa_pss_pss_sha256")
    tls_message.add_signature_hash_algorithm("rsa_pss_pss_sha384")
    tls_message.add_signature_hash_algorithm("rsa_pss_pss_sha512")
    tls_message.add_signature_hash_algorithm("rsa_pss_rsae_sha256")
    tls_message.add_signature_hash_algorithm("rsa_pss_rsae_sha384")
    tls_message.add_signature_hash_algorithm("rsa_pss_rsae_sha512")
    tls_message.add_supported_version("tls1.3")

    # TODO for now we only support sending a single key per Client Hello, but TLS1.3 also allows sending multiple and the server choosing one of them
    # cryptographic_group = "x25519"
    cryptographic_group = "secp256r1"
    tls_message.add_supported_group(cryptographic_group)
    client_private_key, client_public_key, client_key_share = Crypto_Helper.generate_client_keys(cryptographic_group)
    tls_connection.client_public_key = client_public_key
    tls_connection.client_private_key = client_private_key
    tls_message.add_public_key(client_key_share, cryptographic_group)

    # pack the request and send
    packed = TLS_Message_Packer.pack(tls_message)
    # we save the Client Hello in bytes, because we'll need it for calculating the keys
    tls_connection.client_hello_bytes = packed
    print("SENDING: 📤")
    print(packed)
    sock.send(packed)

    while True:
        server_response, server_response_raw = TLS_Message.receive(sock)
        if tls_connection.session != server_response.session:
            raise Exception("Session id doesn't match!")
        print("RECEIVED: 📥")
        # change_cipher_spec (x14/20)
        if server_response.message_type == b"\x14":
            print("Change Cipher Spec")
        # alert (x15/21)
        if server_response.message_type == b"\x15":
            print("Alert")
            # parse back the binary value to the string value so we can print it 
            level_message = list(TLS_Message.ALERT_LEVEL.keys())[list(TLS_Message.ALERT_LEVEL.values()).index(server_response.level.to_bytes(1, TLS_Message.ENDINESS))]
            description_message = list(TLS_Message.ALERT_DESCRIPTION.keys())[list(TLS_Message.ALERT_DESCRIPTION.values()).index(server_response.description.to_bytes(1, TLS_Message.ENDINESS))]
            print("Level: {}, Description: {}".format(level_message, description_message))
            break
        # handshake (x16/22)
        if server_response.message_type == b"\x16":
            print("Handshake")
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
                tls_connection.server_hello_bytes = server_response_raw
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
                break
        # application_data (x17/23)
        if server_response.message_type == b"\x17":
            print("Application Data")
            message = tls_connection.decrypt_message(server_response.application_data, server_response.additional_data)
            print(message)
message