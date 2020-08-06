from message_decoder import Message_Decoder

class TLS_Connection:
    def __init__(self):
        pass

    def decode(self, message):
        private_key = self.client_private_key
        public_key = self.server_public_key
        # x25519 (x00 x1d)
        if self.cryptographic_group == b"\x00\x1d":
            return Message_Decoder.decode_x25519(message, private_key, public_key)
        else:
            raise Exception("Can't decode this cryptographic group yet")
