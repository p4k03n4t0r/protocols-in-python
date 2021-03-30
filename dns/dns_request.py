class Query:
    def __init__(self):
        self.ENDINESS = "big"

    def query_name(self):
        return ".".join(self.name_parts)

    def pack(self):
        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                                               |
        # /                     QNAME                     /
        # /                                               /
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                     QTYPE                     |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                     QCLASS                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        name_length = len(self.name_parts)
        packed = b""

        for i in range(name_length):
            name_part = self.name_parts[i]
            name_part_length = len(name_part)
            # for every name part first add the length
            packed += name_part_length.to_bytes(1, self.ENDINESS)
            for c in name_part:
                # write integer representation of every character as byte: a -> 0x61 -> 01100001
                packed += ord(c).to_bytes(1, self.ENDINESS)
        # end name with a zero
        zero = 0
        packed += zero.to_bytes(1, self.ENDINESS)

        packed += self.qtype.to_bytes(2, self.ENDINESS)
        packed += self.qclass.to_bytes(2, self.ENDINESS)
        return packed


class Answer:
    def __init__(self):
        self.ENDINESS = "big"

    def pack(self):
        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                                               |
        # /                                               /
        # /                      NAME                     /
        # |                                               |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      TYPE                     |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                     CLASS                     |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      TTL                      |
        # |                                               |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                   RDLENGTH                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        # /                     RDATA                     /
        # /                                               /
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        name_length = len(self.name_parts)
        packed = b""

        for i in range(name_length):
            name_part = self.name_parts[i]
            name_part_length = len(name_part)
            # for every name part first add the length
            packed += name_part_length.to_bytes(1, self.ENDINESS)
            for c in name_part:
                # write integer representation of every character as byte: a -> 0x61 -> 01100001
                packed += ord(c).to_bytes(1, self.ENDINESS)
        # end name with a zero
        zero = 0
        packed += zero.to_bytes(1, self.ENDINESS)

        packed += self.atype.to_bytes(2, self.ENDINESS)
        packed += self.aclass.to_bytes(2, self.ENDINESS)
        packed += self.ttl.to_bytes(4, self.ENDINESS)

        rd_length = len(self.rdata_parts)
        packed += rd_length.to_bytes(2, self.ENDINESS)
        for i in range(rd_length):
            packed += self.rdata_parts[i].to_bytes(1, self.ENDINESS)

        return packed


# For full documentation see https://www.ietf.org/rfc/rfc1035.txt chapter 4
class Dns_Request:
    def __init__(self, raw_data):
        self.ENDINESS = "big"

        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      ID                       |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    QDCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    ANCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    NSCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    ARCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        self.id = int.from_bytes(raw_data[:2], self.ENDINESS)
        self.parse_header(int.from_bytes(raw_data[2:4], self.ENDINESS))
        query_count = int.from_bytes(raw_data[4:6], self.ENDINESS)
        answer_count = int.from_bytes(raw_data[6:8], self.ENDINESS)
        ns_count = int.from_bytes(raw_data[8:10], self.ENDINESS)
        ar_count = int.from_bytes(raw_data[10:12], self.ENDINESS)

        byte_counter = 12

        self.queries = []
        if query_count > 0:
            byte_counter = self.parse_queries(raw_data, byte_counter, query_count)
        if answer_count > 0:
            print("Ignoring AN")
        if ns_count > 0:
            print("Ignoring NS")
        self.answers = []
        if ar_count > 0:
            print("Ignoring AR")

    def parse_header(self, header):
        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # due to big ENDINESS read backwards
        self.response_code = header & pow(2, 4)
        header = header >> 4
        # we ignore the next 3 bits, because they're not used (resevered for future use)
        header = header >> 3
        self.recursion_available = header & 1
        header = header >> 1
        self.recursion_desired = header & 1
        header = header >> 1
        self.truncation = header & 1
        header = header >> 1
        self.authoritative_answer = header & 1
        header = header >> 4
        self.opcode = header & pow(2, 4)
        header = header >> 1
        self.is_query = header & 1

    def parse_name_parts(self, raw_data, byte_counter):
        name_parts = []
        while True:
            # every part is prepended by the length of this part
            name_part_length = raw_data[byte_counter]
            byte_counter += 1
            # name ends with a 0 byte
            if name_part_length == 0:
                break
            name_part = ""
            for i in range(name_part_length):
                # each byte can be parsed to a character: 0x61 -> 'a'
                current_byte = raw_data[byte_counter]
                name_part += chr(current_byte)
                byte_counter += 1
            name_parts.append(name_part)

        return name_parts, byte_counter

    def parse_queries(self, raw_data, byte_counter, query_count):
        for i in range(query_count):
            #                                 1  1  1  1  1  1
            #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            # |                                               |
            # /                     QNAME                     /
            # /                                               /
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            # |                     QTYPE                     |
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            # |                     QCLASS                    |
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            query = Query()
            self.queries.append(query)
            # the query name is divided into parts
            query.name_parts, byte_counter = self.parse_name_parts(
                raw_data, byte_counter
            )

            # type of the query: A = 0x01; AAAA = 0x1c;
            query.qtype = int.from_bytes(
                raw_data[byte_counter : byte_counter + 2], self.ENDINESS
            )
            byte_counter += 2
            # class of the query: IN (internet) = 0x01 (often the only one used)
            query.qclass = int.from_bytes(
                raw_data[byte_counter : byte_counter + 2], self.ENDINESS
            )
            byte_counter += 2

        return byte_counter

    def turn_into_response(self, response_code):
        # set the is_query bit to true
        self.is_query = 1
        self.response_code = response_code

    def add_answer(self, hostname, ip, ttl):
        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                                               |
        # /                                               /
        # /                      NAME                     /
        # |                                               |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      TYPE                     |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                     CLASS                     |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      TTL                      |
        # |                                               |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                   RDLENGTH                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        # /                     RDATA                     /
        # /                                               /
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        answer = Answer()
        self.answers.append(answer)
        answer.name_parts = hostname.split(".")
        # type of the query: A = 0x01; AAAA = 0x1c;
        answer.atype = 1
        # class of the query: IN (internet) = 0x01 (often the only one used)
        answer.aclass = 1
        answer.ttl = ttl
        split_ip = ip.split(".")
        answer.rdata_parts = []
        for i in range(len(split_ip)):
            answer.rdata_parts.append(int(split_ip[i]))

    def pack_header(self):
        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # due to big ENDINESS write backwards
        header = self.response_code
        header += self.recursion_available << 7
        header += self.recursion_desired << 8
        header += self.truncation << 9
        header += self.authoritative_answer << 10
        header += self.opcode << 11
        header += self.is_query << 15
        return header.to_bytes(2, self.ENDINESS)

    def pack_queries(self):
        queries = b""
        for i in range(len(self.queries)):
            queries += self.queries[i].pack()
        return queries

    def pack_answers(self):
        answers = b""
        for i in range(len(self.answers)):
            answers += self.answers[i].pack()
        return answers

    def pack(self):
        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      ID                       |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    QDCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    ANCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    NSCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    ARCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        packed = self.id.to_bytes(2, self.ENDINESS)
        packed += self.pack_header()
        packed += len(self.queries).to_bytes(2, self.ENDINESS)
        packed += len(self.answers).to_bytes(2, self.ENDINESS)
        zero = 0
        packed += zero.to_bytes(2, self.ENDINESS)
        packed += zero.to_bytes(2, self.ENDINESS)
        packed += self.pack_queries()
        packed += self.pack_answers()
        return packed
