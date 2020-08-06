class Http_Message: 
    def __init__(self, received_connection, total_match_chunked):
        self.raw = "" 
        self.total_match_chunked = total_match_chunked
        line = self.retrieve_startline(received_connection)
        self.parse_startline(line)

        lines = self.retrieve_headerlines(received_connection)
        self.parse_headerlines(lines)

        # use transfer-encoding above content-length
        if "Transfer-Encoding" in self.headers and self.is_chunked_encoding(self.headers["Transfer-Encoding"]):
            print("Using chunked encoding")
            self.body = self.retrieve_transfer_encoding_body(received_connection)
        elif "Content-Length" in self.headers:
            print("Using content length")
            self.body = self.retrieve_content_length_body(received_connection)
        else:
            self.body = ""

    def is_chunked_encoding(self, header_value):
        if self.total_match_chunked:
            return self.headers['Transfer-Encoding'] == "chunked"
        else:
            return "chunked" in self.headers['Transfer-Encoding']
            
    def retrieve_startline(self, conn):
        line = ""
        while True:
            c = conn.recv(1).decode("ascii")
            line += c
            self.raw += c
            # retrieve characters till end of line is found
            if line.endswith("\r\n"):
                return line.replace("\r\n", "")

    def parse_startline(self, startline):
        line_parts = startline.split(" ")
        if len(line_parts) != 3:
            raise Exception("Startline must be three parts split by spaces: '{}'".format(line_parts))
        self.http_method = line_parts[0]
        self.request_target = line_parts[1]
        self.http_version = line_parts[2]

    def retrieve_headerlines(self, conn):
        lines = []
        line = ""
        while True:
            c = conn.recv(1).decode("ascii")
            line += c
            self.raw += c
            if line.endswith("\r\n"):
                line = line.replace("\r\n", "")
                # headers end with an empty line
                if line == "":
                    break
                lines.append(line)
                line = ""
        return lines

    def parse_headerlines(self, lines):
        self.headers = {}
        for i in range(len(lines)):
            line = lines[i]
            if ": " not in line:
                raise Exception("Header '{}' is missing a semicolon".format(line))
            split_line = line.split(": ", 1)
            self.headers[split_line[0]] = split_line[1]

    def retrieve_content_length_body(self, conn):
        body = ""
        try:
            content_length = int(self.headers["Content-Length"])
        except ValueError:
            raise Exception("Content-Length must be a number")
        for i in range(content_length):
            c = conn.recv(1).decode("ascii")
            body += c
            self.raw += c

        # body ends with line break
        self.retrieve_line_break(conn)
        return body
    
    def retrieve_transfer_encoding_body(self, conn):
        body = ""
        length_line = ""
        while True:
            c = conn.recv(1).decode("ascii")
            length_line += c
            self.raw += c
            if length_line.endswith("\r\n"):
                length_line = length_line.replace("\r\n", "")
                try:
                    length = int(length_line, 16)
                except ValueError:
                    raise Exception("Invalid length for chunked encoding part '{}'".format(length_line))
                if length == 0:
                    break
                chunk = ""
                for i in range(length + 2):
                    c = conn.recv(1).decode("ascii")
                    chunk += c
                    self.raw += c
                if not chunk.endswith("\r\n"):
                    raise Exception("Chunk '{}' should end with a linebreak".format(chunk))
                body += chunk.replace("\r\n", "")
                length_line = ""

        # body ends with line break
        self.retrieve_line_break(conn)

        return body

    def retrieve_line_break(self, conn):
        line = ""
        line += conn.recv(1).decode("ascii")
        line += conn.recv(1).decode("ascii")
        self.raw += line
        if line != "\r\n":
            raise Exception("Expected a line break '{}'".format(line))

    def get_response(self, status_code):
        # return line has format 'http-version status-code status-message'
        if status_code == 403:
            status_message = "FORBIDDEN"
        else:
            status_message = "OK"
        response = "{} {} {}\r\n".format(self.http_version, status_code, status_message)

        # if a 2xx status code is returned, then based on the request url set the return body
        if status_code >= 200 and status_code < 300:
            if self.request_target == "/flag":
                self.body = "THIS_IS_FLAG\n"
            else:
                self.body = "Hello you!!!\n"

        # if a body is set, set the content-length
        if self.body is not None and len(self.body) > 0:
            self.headers["Content-Length"] = str(len(self.body))

        # add headers
        for key in self.headers:
            response += "{}: {}\r\n".format(key, self.headers[key])

        # add extra line break after the headers
        response += "\r\n"

        # if content-length is set, append the body
        if "Content-Length" in self.headers:
            response += self.body + "\r\n"

        # end with enter
        response += "\r\n"
        return response