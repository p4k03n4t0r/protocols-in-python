from crypto_helper import Crypto_Helper

# This method offers helper methods to pack an instance of a TLS_Message into bytes
class TLS_Message_Packer:
    @staticmethod
    def pack_tls_message(tls_message, client_handshake_key, client_handshake_iv, counter):
        # change_cipher_spec (x14/20)
        if tls_message.message_type == b"\x14":
            # this message type always has a body with 0x01
            message = b"\x01"
        # alert (x15/19)
        elif tls_message.message_type == b"\x15":
            raise Exception("Packing alert is not yet supported")
        # handshake (x16/22) or application_data (x17/23)
        elif tls_message.message_type == b"\x16" or tls_message.message_type == b"\x17":            
            # we pack the request backwards, because we have to know the length of the other parts
            handshake_content = TLS_Message_Packer.pack_handshake_content(tls_message)
            # use the length of the client_hello_header in the handshake_header
            handshake_header = TLS_Message_Packer.pack_handshake_header(tls_message, len(handshake_content))
            # prepend the handshake_header before the client_hello_header
            message = handshake_header + handshake_content

        # we keep this message because we need this one for the transcript
        transcript_message = message
        # application_data (x17/23)
        if tls_message.message_type == b"\x17":
            # additional data is a combination of the record fields of this package
            # see https://tools.ietf.org/html/rfc8446#section-5.2 (the || mean concating not a logical OR operation)
            additional_data = tls_message.message_type + tls_message.message_version + int.to_bytes(len(message))
            # for application data we still have to encrypt the message
            message = Crypto_Helper.aead_encrypt(message, additional_data, client_handshake_key, client_handshake_iv, counter)
            raise Exception("Not implemented yet")

        # use the combined length of the handshake_header and client_hello_header in the record_header
        # prepend the record_header before the message
        packed = TLS_Message_Packer.pack_record_header(tls_message, len(message)) + message
        packed_transcript = TLS_Message_Packer.pack_record_header(tls_message, len(transcript_message)) + transcript_message
        return packed, packed_transcript

    @staticmethod
    def pack_record_header(tls_message, message_length):
        record_header = tls_message.message_type
        record_header += tls_message.message_version
        # size of handshake message that follows
        record_header += message_length.to_bytes(2, tls_message.ENDINESS)
        return record_header 

    @staticmethod
    def pack_handshake_header(handshake, handshake_content_length):
        handshake_header = handshake.handshake_type
        # size of content of the handshakemessage that will follow
        handshake_header += handshake_content_length.to_bytes(3, handshake.ENDINESS)
        return handshake_header

    @staticmethod
    def pack_handshake_content(tls_message):
        # see https://tools.ietf.org/html/rfc8446#section-4
        # client_hello (x01/01)
        if tls_message.handshake_type == b"\x01":
            return TLS_Message_Packer.pack_client_hello(tls_message)  
        # finished (x14/20)
        elif tls_message.handshake_type == b"\x14":
            return TLS_Message_Packer.pack_verify(tls_message)
        else:
            raise Exception("Handshake type can't be packed yet: {}".format(tls_message.handshake_type))

    @staticmethod
    def pack_client_hello(handshake):
        # see https://tools.ietf.org/html/rfc8446#section-4.1.2
        # Client Version
        client_hello_packed = handshake.handshake_version

        # Client Random: 32 bytes of random data
        client_hello_packed += handshake.client_random

        # Session ID: In TLS 1.3 the session is done using PSK (pre-shared keys) mechanism, so this field is no longer needed for that purpose. 
        # Instead a non-empty value in this field is used to trigger "middlebox compatibility mode" which helps TLS 1.3 sessions to be disguised as resumed TLS 1.2 sessions.
        if handshake.session is None:
            session_length = 32
            handshake.session = handshake.get_random_number(session_length).to_bytes(session_length, handshake.ENDINESS)
        # length of the session ID
        client_hello_packed += len(handshake.session).to_bytes(1, handshake.ENDINESS)
        # random session ID
        client_hello_packed += handshake.session

        # Cipher Suites: The client provides an ordered list of which cipher suites it will support for encryption. 
        # The list is in the order preferred by the client, with highest preference first.
        cipher_bytes = b"".join(handshake.ciphers)
        # length of the ciphers in bytes
        client_hello_packed += len(cipher_bytes).to_bytes(2, handshake.ENDINESS)
        client_hello_packed += cipher_bytes

        # Compression Methods: TLS 1.3 no longer allows compression, so this field is always a single entry with the "null" compression method which performs no change to the data.
        # length of compression methods in bytes
        client_hello_packed += b"\x01"
        # 0x00 indicates "null" compression
        client_hello_packed += b"\x00"

        # Extensions: optional extensions the client can provide 
        extensions_header = TLS_Message_Packer.pack_extensions_header(handshake)
        # length of the extensions header
        client_hello_packed += len(extensions_header).to_bytes(2, handshake.ENDINESS)
        client_hello_packed += extensions_header

        return client_hello_packed

    @staticmethod
    def pack_verify(handshake):
        # see https://tools.ietf.org/html/rfc8446#section-4.4.4
        return handshake.client_verify_data

    @staticmethod
    def pack_extensions_header(handshake):
        # for all extensions see https://tools.ietf.org/html/rfc8446#section-4.2
        # append extensions when provided
        # the first two bytes indicate the type of extension
        extensions_header = b""

        # Extension - Server Name (0x00 0x00): The client has provided the name of the server it is contacting, also known as SNI (Server Name Indication).
        # Without this extension a HTTPS server would not be able to provide service for multiple hostnames (virtual hosts) on a single IP address because it couldn't know which hostname's certificate to send until after the TLS session was negotiated and the HTTP request was made.
        # 0x00 indicates the type, which is "DNS Hostname" in this case
        if handshake.server_name is not None:
            extensions_header += TLS_Message_Packer.pack_extension(handshake, b"\x00\x00", [{b"\x00": handshake.server_name.encode("ascii")}])
        # Extension - Supported Groups (0x00 0x2b): The client has indicated that it supports elliptic curve (EC) cryptography for three curve types. To make this extension more generic for other cryptography types it now calls these "supported groups" instead of "supported curves".
        # This list is presented in descending order of the client's preference.
        extensions_header += TLS_Message_Packer.pack_extension(handshake, b"\x00\x0a", handshake.supported_groups)
        # Extension - Signature Algorithms (0x00 0x2b): This extension indicates which signature algorithms the client supports. This can influence the certificate that the server presents to the client, as well as the signature that is sent by the server in the CertificateVerify record.
        # This list is presented in descending order of the client's preference.
        extensions_header += TLS_Message_Packer.pack_extension(handshake, b"\x00\x0d", handshake.signature_algorithms)
        # Extension - Key Share (0x00 0x33): The client sends one or more public keys using an algorithm that it thinks the server will support. This allows the rest of the handshake after the ClientHello and ServerHello messages to be encrypted, unlike previous protocol versions where the handshake was sent in the clear.
        extensions_header += TLS_Message_Packer.pack_extension(handshake, b"\x00\x33", handshake.public_keys)
        # Extension - Supported Versions (0x00 0x2b): supported TLS versions, the length indicating each version entry is 1 byte (because fuck logic)
        extensions_header += TLS_Message_Packer.pack_extension(handshake, b"\x00\x2b", handshake.supported_versions, 1)

        return extensions_header

    @staticmethod
    def pack_extension(handshake, extension_code, extension_values, list_entry_bytes_length = 2):
        if len(extension_values) == 0:
            return b""

        extension_bytes = b""
        for extension_value in extension_values:
            # if this extension value is made up of two values, we have to add them both 
            if isinstance(extension_value, dict):
                # retrieve the key and value form the dictionary 
                key = list(extension_value.keys())[0]
                value = extension_value[key]
                extension_value_bytes = value
                # prepend the value with the length of the value in bytes
                extension_value_bytes = len(extension_value_bytes).to_bytes(2, handshake.ENDINESS) + extension_value_bytes
                # prepend with the key
                extension_value_bytes = key + extension_value_bytes
                # append the bytes
                extension_bytes += extension_value_bytes
            # if this extension value is a single value, just append it
            else:
                extension_bytes += extension_value
        # prepend length of this list entry
        extension_bytes = len(extension_bytes).to_bytes(list_entry_bytes_length, handshake.ENDINESS) + extension_bytes
        # prepend length of all the list entries (in this case that's only one)
        extension_bytes = len(extension_bytes).to_bytes(2, handshake.ENDINESS) + extension_bytes
        # prepend the byte code indicating the type of extension 
        extension_bytes = extension_code + extension_bytes
        return extension_bytes