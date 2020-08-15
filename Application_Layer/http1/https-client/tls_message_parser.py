from tls_message import TLS_Message
from crypto_helper import Crypto_Helper

class TLS_Message_Parser:
    ENDINESS = 'big'

    @staticmethod
    def parse_tls_message(message_type_bytes, message_version_bytes, record_length_bytes, raw_content):
        tls_message = TLS_Message(message_type_bytes, message_version_bytes)
        # see https://tools.ietf.org/html/rfc8446#section-5.1
        # Change Cipher Spec (x14/20) 
        if tls_message.message_type == b"\x14":
            # the Change Cipher Spec message doesn't have a body
            pass
        # Alert (x15/21)
        elif tls_message.message_type == b"\x15":
            TLS_Message_Parser.parse_alert_content(tls_message, raw_content)
        # Handshake (x16/22)
        elif tls_message.message_type == b"\x16":
            TLS_Message_Parser.parse_handshake_content(tls_message, raw_content)
        # Application Data (x17/23)
        elif tls_message.message_type == b"\x17":
            # the whole content is the application data
            tls_message.application_data = raw_content
            # additional data is a combination of the record fields of this package
            # see https://tools.ietf.org/html/rfc8446#section-5.2 (the || mean concating not a logical OR operation)
            tls_message.additional_data = message_type_bytes + message_version_bytes + record_length_bytes
        else:
            raise Exception("Can't handle this message type yet: {}".format(message_type_bytes))
        return tls_message

    @staticmethod
    def parse_alert_content(tls_message, raw_handshake):
        # see https://tools.ietf.org/html/rfc8446#section-6
        # struct {
        #   AlertLevel level;
        #   AlertDescription description;
        # } Alert;
        tls_message.level = raw_handshake[0]
        tls_message.description = raw_handshake[1]

    @staticmethod
    def parse_handshake_content(tls_message, raw_handshake):
        i = 0

        # handshake type (1 byte)
        tls_message.handshake_type = bytes([raw_handshake[i]])
        i += 1

        # handshake length (3 bytes)
        handshake_content_length = int.from_bytes(raw_handshake[i:i+3], TLS_Message_Parser.ENDINESS)
        i += 3

        if i + handshake_content_length != len(raw_handshake):
            raise Exception("Invalid length of handshake content")

        handshake_content = raw_handshake[i:i+handshake_content_length]

        # for all types see https://tools.ietf.org/html/rfc8446#section-4
        # Client Hello (x01/01)
        if tls_message.handshake_type == b"\x01":
            TLS_Message_Parser.parse_hello(tls_message, handshake_content)
        # Server Hello (or Client Hello Retry) (x02/02)
        elif tls_message.handshake_type == b"\x02":
            TLS_Message_Parser.parse_hello(tls_message, handshake_content)
        # Encrypted Extensions (x08/08)
        elif tls_message.handshake_type == b"\x08":
            # TODO parse and handle Encrypted Extensions
            print("IGNORING ENCRYPTED EXTENSIONS (for now)")
            pass # see https://tools.ietf.org/html/rfc8446#section-4.3.1
        # Certificate (x0b\11)
        elif tls_message.handshake_type == b"\x0b":
            TLS_Message_Parser.parse_certificate_data(tls_message, handshake_content)
        # CertificateVerify (x0f\15)
        elif tls_message.handshake_type == b"\x0f": 
            TLS_Message_Parser.parse_certificate_verify(tls_message, handshake_content)
        # Finished (x14\20)
        elif tls_message.handshake_type == b"\x14":
            print("IGNORING FINISHED (for now)")
            pass # see https://tools.ietf.org/html/rfc8446#section-4.4.4
        else:
            raise Exception("Received handshake type that is unknown or can't be parsed yet: {}".format(tls_message.handshake_type))


    @staticmethod
    def parse_hello(tls_message, handshake_content):
        # see https://tools.ietf.org/html/rfc8446#section-4.1.2
        # TODO split hello messages in seperate parsers (in hindsight they have a different structure)
        # struct {
        #     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
        #     Random random;
        #     opaque legacy_session_id_echo<0..32>;
        #     CipherSuite cipher_suite;
        #     uint8 legacy_compression_method = 0;
        #     Extension extensions<6..2^16-1>;
        # } ServerHello;
        # uint16 ProtocolVersion;
        # opaque Random[32];
        # uint8 CipherSuite[2];    /* Cryptographic suite selector */
        # struct {
        #     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
        #     Random random;
        #     opaque legacy_session_id<0..32>;
        #     CipherSuite cipher_suites<2..2^16-2>;
        #     opaque legacy_compression_methods<1..2^8-1>;
        #     Extension extensions<8..2^16-1>;
        # } ClientHello;

        i = 0
        # handshake version (tls1.0 x03x01, tls1.1 x03x02, tls1.2 x03x03, tls1.3 x03x04)
        tls_message.handshake_version = handshake_content[i:i+2]
        i += 2

        # random value (32 bytes)
        tls_message.random = handshake_content[i:i+32]
        i += 32

        # session id
        session_id_length = handshake_content[i]
        i += 1
        offset = session_id_length
        tls_message.session_id = handshake_content[i:i+offset]
        i += offset

        # cipher suite to use
        tls_message.cipher_suite = handshake_content[i:i+2]
        i += 2

        # skip compression method, which is not used 
        i += 1

        # ignore extensions_length, since we already know the length
        # TODO not ignore this one (:
        i += 2

        # parse the extensions, see https://tools.ietf.org/html/rfc8446#section-4.2
        # TODO parse all extensions
        # struct {
        #     ExtensionType extension_type;
        #     opaque extension_data<0..2^16-1>;
        # } Extension;
        # enum {
        #     server_name(0),                             /* RFC 6066 */
        #     max_fragment_length(1),                     /* RFC 6066 */
        #     status_request(5),                          /* RFC 6066 */
        #     supported_groups(10),                       /* RFC 8422, 7919 */
        #     signature_algorithms(13),                   /* RFC 8446 */
        #     use_srtp(14),                               /* RFC 5764 */
        #     heartbeat(15),                              /* RFC 6520 */
        #     application_layer_protocol_negotiation(16), /* RFC 7301 */
        #     signed_certificate_timestamp(18),           /* RFC 6962 */
        #     client_certificate_type(19),                /* RFC 7250 */
        #     server_certificate_type(20),                /* RFC 7250 */
        #     padding(21),                                /* RFC 7685 */
        #     pre_shared_key(41),                         /* RFC 8446 */
        #     early_data(42),                             /* RFC 8446 */
        #     supported_versions(43),                     /* RFC 8446 */
        #     cookie(44),                                 /* RFC 8446 */
        #     psk_key_exchange_modes(45),                 /* RFC 8446 */
        #     certificate_authorities(47),                /* RFC 8446 */
        #     oid_filters(48),                            /* RFC 8446 */
        #     post_handshake_auth(49),                    /* RFC 8446 */
        #     signature_algorithms_cert(50),              /* RFC 8446 */
        #     key_share(51),                              /* RFC 8446 */
        #     (65535)
        # } ExtensionType;

        while i < len(handshake_content):
            extension_type = handshake_content[i:i+2]
            i += 2
            extension_length = int.from_bytes(handshake_content[i:i+2], tls_message.ENDINESS)
            i += 2
            # Extension: Supported Versions
            if extension_type == b"\x00\x2b":
                for j in range(i, i + extension_length, 2):
                    tls_message.supported_version = handshake_content[j:j+2]
                    i += 2
            # Extension: Key Share
            elif extension_type == b"\x00\x33":
                # the Key Share could have two formats:
                # 1) if length is 2 this is a HelloRetryRequest and only a single supported group is given
                # 2) if length is longer than 2 this is a ServerHello and also the key exchange is given
                tls_message.supported_group = handshake_content[i:i+2]
                i += 2
                if extension_length > 2:
                    key_exchange_length = int.from_bytes(handshake_content[i:i+2], tls_message.ENDINESS)
                    i += 2
                    tls_message.key_exchange = handshake_content[i:i+key_exchange_length]
                    i += key_exchange_length
    

    @staticmethod
    def parse_application_data(application_data):
        end_byte = application_data[len(application_data)-1:]
        # application data should end with a specific byte
        if end_byte != b"\x16":
            raise Exception("Application data should end with a x16 byte")
        # remove the last byte
        application_data = application_data[:-1]
        
        # we create a new TLS_Message in the form of a handshake message
        # a bit dirty to hardcode the type (handshake x16) and version (tls1.3 x03x04), but should be okay for now
        tls_message = TLS_Message_Parser.parse_tls_message(b"\x16", b"\x03\04", len(application_data), application_data)
        return tls_message

    @staticmethod
    def parse_certificate_data(tls_message, handshake_content):
        # see https://tools.ietf.org/html/rfc8446#section-4.4.2
        # enum {
        #     X509(0),
        #     RawPublicKey(2),
        #     (255)
        # } CertificateType;
        # struct {
        #     select (certificate_type) {
        #         case RawPublicKey:
        #             /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
        #             opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
        #         case X509:
        #             opaque cert_data<1..2^24-1>;
        #     };
        #     Extension extensions<0..2^16-1>;
        # } CertificateEntry;
        # struct {
        #     opaque certificate_request_context<0..2^8-1>;
        #     CertificateEntry certificate_list<0..2^24-1>;
        # } Certificate;

        i = 0
        request_context = bytes([handshake_content[i]])
        i += 1
        # this message is not in response to a certificate request, so we expect the request context to be empty
        if request_context != b"\x00":
            raise Exception("request_context is expected to be empty")

        certificates_length = int.from_bytes(handshake_content[i:i+3], TLS_Message_Parser.ENDINESS)
        i += 3

        # this should be it, so the index should match the length of the content
        if i + certificates_length != len(handshake_content):
            raise Exception("Invalid length for the certificates data")

        # we parse all certificates
        # tls_message.certificates = []
        # TODO for now we only expect a single certificate
        # while i < len(handshake_content):
        certificate_length = int.from_bytes(handshake_content[i:i+3], TLS_Message_Parser.ENDINESS)
        i += 3

        # if i > len(handshake_content):
        #     raise Exception("Invalid length for a certificate")

        raw_certificate = handshake_content[i:]
        i += certificate_length

        # tls_message.certificates.append(Crypto_Helper.parse_certificate(raw_certificate))
        tls_message.certificate = Crypto_Helper.parse_certificate(raw_certificate)

    @staticmethod
    def parse_certificate_verify(tls_message, handshake_content):
        # see https://tools.ietf.org/html/rfc8446#section-4.4.3

        pass
