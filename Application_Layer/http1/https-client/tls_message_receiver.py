from tls_message_parser import TLS_Message_Parser

class TLS_Message_Receiver:
    ENDINESS = 'big'
    
    @staticmethod
    def receive(socket):
        # also track and return the raw_message since we might need this later
        raw_message = b""

        # receive the message type
        message_type_bytes = socket.recv(1)
        raw_message += message_type_bytes

        # receive the message TLS version
        message_version_bytes = socket.recv(2)
        raw_message += message_version_bytes

        # receive the length of message and the message itself using this length
        record_length_bytes = socket.recv(2)
        record_length = int.from_bytes(record_length_bytes, TLS_Message_Receiver.ENDINESS)
        raw_message += record_length_bytes
        raw_content = socket.recv(record_length)
        raw_message += raw_content

        tls_message = TLS_Message_Parser.parse_tls_message(message_type_bytes, message_version_bytes, record_length_bytes, raw_content)

        return tls_message, raw_message