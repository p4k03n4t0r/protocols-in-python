class TLS_Message_Parser:

    @staticmethod
    def parse_alert(tls_message, raw_handshake):
        tls_message.level = raw_handshake[0]
        tls_message.description = raw_handshake[1]

    @staticmethod
    def parse_handshake(tls_message, raw_handshake):
        i = 0
        # handshake type (Client Hello 0x01, Server Hello 0x02)
        tls_message.handshake_type = raw_handshake[i]
        i += 1

        # ignore handshake length (3 bytes), since we already know the length
        i += 3

        # handshake version (tls1.0 x03x01, tls1.1 x03x02, tls1.2 x03x03, tls1.3 x03x04)
        tls_message.handshake_version = raw_handshake[i:i+2]
        i += 2

        # random value (32 bytes)
        tls_message.random = raw_handshake[i:i+32]
        i += 32

        # session id
        session_id_length = raw_handshake[i]
        i += 1
        offset = session_id_length
        tls_message.session_id = raw_handshake[i:i+offset]
        i += offset

        # cipher suite to use
        tls_message.cipher_suite = raw_handshake[i:i+2]
        i += 2

        # skip compression method, which is not used 
        i += 1

        # ignore extensions_length, since we already know the length
        i += 2
        # parse the extensions array
        # TODO also parse the other extensions (needed if we want to be the server)
        while i < len(raw_handshake):
            extension_type = raw_handshake[i:i+2]
            i += 2
            extension_length = int.from_bytes(raw_handshake[i:i+2], tls_message.ENDINESS)
            i += 2
            # Extension: Supported Versions
            if extension_type == b"\x00\x2b":
                for j in range(i, i + extension_length, 2):
                    tls_message.supported_version = raw_handshake[j:j+2]
                    i += 2
            # Extension: Key Share
            elif extension_type == b"\x00\x33":
                # the Key Share could have two formats:
                # 1) if length is 2 this is a HelloRetryRequest and only a single supported group is given
                # 2) if length is longer than 2 this is a ServerHello and also the key exchange is given
                tls_message.supported_group = raw_handshake[i:i+2]
                i += 2
                if extension_length > 2:
                    key_exchange_length = int.from_bytes(raw_handshake[i:i+2], tls_message.ENDINESS)
                    i += 2
                    tls_message.key_exchange = raw_handshake[i:i+key_exchange_length]
                    i += key_exchange_length
